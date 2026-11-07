#!/usr/bin/env python3
"""Fake authoritative server for the cluster-compose harness.

Zone <zone> (default test.):
  apex SOA/NS, ns.<zone> A
  n<k>.<zone>   A    for 0 <= k < NAMES (default 1000000), TTL configurable
  *.w.<zone>    A    wildcard (any depth below w.<zone>)
  anything else      NXDOMAIN (+SOA)
  other qtypes for existing names: NODATA (+SOA)

Per-query delay is configurable at runtime.  Every query is counted per
(qname, source ip) so that duplicate upstream fetches can be attributed.

HTTP control/stats on port 8080:
  GET /config?delay_ms=500&ttl=300&servfail=0     set runtime parameters
  GET /reset                                      clear counters
  GET /summary                                    JSON summary (see below)
  GET /counts[?prefix=n1]                         {qname: [raw, distinct_src]}
  GET /counts_src?name=n1.test.                   {src: count}
UDP/TCP DNS on port 53.
"""
import asyncio, json, os, re, sys, threading, time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import dns.message, dns.name, dns.rrset, dns.rdatatype, dns.rdataclass, dns.rcode, dns.flags, dns.rdata

ZONE = os.environ.get("ZONE", "test.").lower()
NAMES = int(os.environ.get("NAMES", "1000000"))
cfg = {"delay_ms": 0.0, "ttl": 3600, "servfail": 0}
counts = {}            # qname -> {src: n}
qtype_counts = defaultdict(int)
total = [0]
started = time.time()
zone_name = dns.name.from_text(ZONE)
NPAT = re.compile(r"^n(\d+)$")
SOA = "ns.%s hostmaster.%s 1 3600 600 86400 30" % (ZONE, ZONE)


def answer(q):
    r = dns.message.make_response(q)
    r.flags |= dns.flags.AA
    r.flags &= ~dns.flags.RA
    question = q.question[0]
    qn = question.name
    qt = question.rdtype
    ttl = int(cfg["ttl"])
    if not qn.is_subdomain(zone_name):
        r.set_rcode(dns.rcode.REFUSED)
        return r
    rel = qn.relativize(zone_name).to_text().lower()
    soa = dns.rrset.from_text(zone_name, 30, "IN", "SOA", SOA)
    exists = False
    rdata = None
    if rel == "@":
        exists = True
        if qt == dns.rdatatype.SOA:
            r.answer.append(soa)
            return r
        if qt == dns.rdatatype.NS:
            r.answer.append(dns.rrset.from_text(qn, ttl, "IN", "NS", "ns." + ZONE))
            r.additional.append(dns.rrset.from_text("ns." + ZONE, ttl, "IN", "A", "192.0.2.53"))
            return r
    elif rel == "ns":
        exists = True
        rdata = "192.0.2.53"
    else:
        m = NPAT.match(rel)
        if m and int(m.group(1)) < NAMES:
            exists = True
            k = int(m.group(1))
            rdata = "10.%d.%d.%d" % ((k >> 16) & 255, (k >> 8) & 255, k & 255)
        elif rel == "w" or rel.endswith(".w"):
            exists = True
            rdata = "198.51.100.7"
    if not exists:
        r.set_rcode(dns.rcode.NXDOMAIN)
        r.authority.append(soa)
        return r
    if qt == dns.rdatatype.A and rdata:
        r.answer.append(dns.rrset.from_text(qn, ttl, "IN", "A", rdata))
    else:
        r.authority.append(soa)
    return r


def handle(data, src):
    try:
        q = dns.message.from_wire(data)
        question = q.question[0]
    except Exception:
        return None, 0.0
    name = question.name.to_text().lower()
    d = counts.get(name)
    if d is None:
        d = counts[name] = {}
    d[src] = d.get(src, 0) + 1
    total[0] += 1
    qtype_counts[dns.rdatatype.to_text(question.rdtype)] += 1
    if cfg["servfail"] and (total[0] % int(cfg["servfail"])) == 0:
        r = dns.message.make_response(q)
        r.set_rcode(dns.rcode.SERVFAIL)
    else:
        r = answer(q)
    return r.to_wire(), cfg["delay_ms"] / 1000.0


class UDP(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        wire, delay = handle(data, addr[0])
        if wire is None:
            return
        if delay > 0:
            asyncio.get_running_loop().call_later(delay, self.t.sendto, wire, addr)
        else:
            self.t.sendto(wire, addr)


async def tcp_client(reader, writer):
    src = writer.get_extra_info("peername")[0]
    try:
        while True:
            hdr = await reader.readexactly(2)
            data = await reader.readexactly(int.from_bytes(hdr, "big"))
            wire, delay = handle(data, src)
            if wire is None:
                break
            if delay > 0:
                await asyncio.sleep(delay)
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
    except Exception:
        pass
    writer.close()


def summary():
    snap = list(counts.items())
    raw_hist = defaultdict(int)
    src_hist = defaultdict(int)
    raw_total = 0
    src_total = 0
    nm = 0
    for name, d in snap:
        if not name.startswith("n") and not name.startswith("x"):
            pass
        raw = sum(d.values())
        raw_hist[raw] += 1
        src_hist[len(d)] += 1
        raw_total += raw
        src_total += len(d)
        nm += 1
    return {"total_queries": total[0], "distinct_names": nm,
            "raw_per_name_mean": raw_total / nm if nm else 0,
            "src_per_name_mean": src_total / nm if nm else 0,
            "raw_hist": dict(sorted(raw_hist.items())),
            "src_hist": dict(sorted(src_hist.items())),
            "qtypes": dict(qtype_counts), "config": cfg, "uptime": time.time() - started}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/config":
            for k, v in qs.items():
                if k in cfg:
                    cfg[k] = float(v) if k == "delay_ms" else int(v)
            out = cfg
        elif u.path == "/reset":
            counts.clear(); qtype_counts.clear(); total[0] = 0
            out = {"ok": 1}
        elif u.path == "/summary":
            out = summary()
        elif u.path == "/counts":
            pre = qs.get("prefix", "")
            out = {n: [sum(d.values()), len(d)] for n, d in list(counts.items()) if n.startswith(pre)}
        elif u.path == "/counts_src":
            out = counts.get(qs.get("name", ""), {})
        else:
            out = {"error": "unknown"}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDP, local_addr=("0.0.0.0", 53))
    await asyncio.start_server(tcp_client, "0.0.0.0", 53)
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("authority up zone=%s names=%d" % (ZONE, NAMES), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
