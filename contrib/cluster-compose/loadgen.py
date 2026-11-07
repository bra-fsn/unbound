#!/usr/bin/env python3
"""Async UDP DNS load generator (stdlib only) for the cluster-compose harness.

Writes one CSV row per query: t_send(epoch s), target, qname, latency_ms,
rcode (-1 = client timeout), ancount.

Modes:
  pool    K names n<base>..n<base+K-1>, each queried --rounds times in total,
          shuffled, each to a random target, at --rate qps.
  stream  fresh names n<base+i>, --rate name-groups/s for --duration s; each
          group sends the name to --fanout distinct random targets at the
          same instant (fanout >= #targets: thundering herd).
  sched   lines "offset_seconds target qname" from --file, fired at those times.
  list    lines "target qname" from --file, --concurrency in flight (closed
          loop), in order.
"""
import argparse, asyncio, json, random, struct, sys, time


def build(qid, qname, qtype=1):
    out = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for lab in qname.rstrip(".").split("."):
        b = lab.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00" + struct.pack("!HH", qtype, 1)


class Target(asyncio.DatagramProtocol):
    def __init__(self, ip, port, timeout, rows):
        self.ip, self.port, self.timeout, self.rows = ip, port, timeout, rows
        self.pend = {}
        self.nextid = random.randrange(65536)

    async def start(self):
        loop = asyncio.get_running_loop()
        self.t, _ = await loop.create_datagram_endpoint(lambda: self, remote_addr=(self.ip, self.port))

    def datagram_received(self, data, addr):
        if len(data) < 12:
            return
        qid, flags, _, an = struct.unpack("!HHHH", data[:8])
        e = self.pend.pop(qid, None)
        if e is None:
            return
        t0, wall, qname, fut, th = e
        th.cancel()
        lat = (time.perf_counter() - t0) * 1000
        self.rows.append((wall, self.ip, qname, lat, flags & 15, an))
        fut.set_result(None)

    def error_received(self, exc):
        pass

    async def ask(self, qname):
        loop = asyncio.get_running_loop()
        while True:
            self.nextid = (self.nextid + 1) & 0xffff
            if self.nextid not in self.pend:
                break
        qid = self.nextid
        fut = loop.create_future()
        t0 = time.perf_counter()
        wall = time.time()

        def to():
            if self.pend.pop(qid, None) is not None:
                self.rows.append((wall, self.ip, qname, self.timeout * 1000, -1, 0))
                fut.set_result(None)
        th = loop.call_later(self.timeout, to)
        self.pend[qid] = (t0, wall, qname, fut, th)
        self.t.sendto(build(qid, qname))
        await fut


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["pool", "stream", "list", "sched"])
    ap.add_argument("--targets", default="")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--zone", default="test")
    ap.add_argument("--base", type=int, default=0)
    ap.add_argument("--count", type=int, default=100, help="pool: K names")
    ap.add_argument("--rounds", type=int, default=4, help="pool: queries per name")
    ap.add_argument("--rate", type=float, default=500)
    ap.add_argument("--duration", type=float, default=10)
    ap.add_argument("--fanout", type=int, default=1)
    ap.add_argument("--file", default="")
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    random.seed(a.seed)
    rows = []
    ips = [x for x in a.targets.split(",") if x]
    tg = {}
    lock = asyncio.Lock()
    async def get(ip):
        async with lock:
            if ip not in tg:
                t = Target(ip, a.port, a.timeout, rows)
                await t.start()
                tg[ip] = t
        return tg[ip]
    for ip in ips:
        await get(ip)
    nm = lambda i: "n%d.%s." % (i, a.zone)
    tasks = []
    t0 = time.perf_counter()
    loop = asyncio.get_running_loop()

    async def fire(ip, name):
        await (await get(ip)).ask(name)

    if a.mode in ("pool", "stream"):
        items = []   # (t_offset, [(ip,name)...])
        if a.mode == "pool":
            seq = [i for i in range(a.base, a.base + a.count) for _ in range(a.rounds)]
            random.shuffle(seq)
            for k, i in enumerate(seq):
                items.append((k / a.rate, [(random.choice(ips), nm(i))]))
        else:
            n = int(a.duration * a.rate)
            for k in range(n):
                t = ips if a.fanout >= len(ips) else random.sample(ips, a.fanout)
                items.append((k / a.rate, [(ip, nm(a.base + k)) for ip in t]))
        for off, grp in items:
            d = t0 + off - time.perf_counter()
            if d > 0:
                await asyncio.sleep(d)
            for ip, name in grp:
                tasks.append(loop.create_task(fire(ip, name)))
        if tasks:
            await asyncio.gather(*tasks)
    elif a.mode == "sched":
        sc = sorted((float(o), ip, nmx) for o, ip, nmx in (l.split() for l in open(a.file) if l.strip()))
        for off, ip, name in sc:
            d = t0 + off - time.perf_counter()
            if d > 0:
                await asyncio.sleep(d)
            tasks.append(loop.create_task(fire(ip, name)))
        if tasks:
            await asyncio.gather(*tasks)
    else:
        lines = [l.split() for l in open(a.file) if l.strip()]
        it = iter(lines)
        async def worker():
            for ip, name in it:
                await fire(ip, name)
        await asyncio.gather(*[worker() for _ in range(a.concurrency)])
    el = time.perf_counter() - t0
    rows.sort()
    with open(a.out, "w") as f:
        f.write("t,target,qname,lat_ms,rcode,an\n")
        for r in rows:
            f.write("%.4f,%s,%s,%.3f,%d,%d\n" % r)
    print(json.dumps({"queries": len(rows), "elapsed": el,
                      "timeouts": sum(1 for r in rows if r[4] == -1),
                      "servfail": sum(1 for r in rows if r[4] == 2)}))

asyncio.run(main())
