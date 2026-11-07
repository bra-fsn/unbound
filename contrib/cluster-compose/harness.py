#!/usr/bin/env python3
"""Multi-instance test + benchmark harness for the unbound cluster module.

Host side driver (python3 stdlib only, needs docker + compose plugin).  See
README.md.  It builds the images, generates docker-compose.yml and per-node
unbound.conf into the output directory, runs the scenarios and writes
report.md + results.json + raw data.
"""
import argparse, concurrent.futures as cf, csv, datetime, json, os, re, shutil
import statistics, subprocess, sys, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = "/etc/unbound-node/unbound.conf"
ALL = ["a", "b", "c", "c2", "d", "d2", "e", "e2", "e3", "e4", "f", "g", "g2", "h", "i", "j", "k"]
TITLES = {
    "a": "Baseline vs cluster, K distinct names from random nodes",
    "b": "Thundering herd (all nodes ask the same fresh name)",
    "c": "Owner dead: docker stop, then start",
    "c2": "Owner process dead, host alive (port closed): ICMP port unreachable",
    "d": "Owner silent: docker pause, then unpause",
    "d2": "Owner silent: tc netem loss 100%, then removed",
    "e": "Owner slow: netem delay 200ms (above the 100 ms deadline)",
    "e2": "Owner jittery: netem delay 50ms +-40ms (below the deadline)",
    "e3": "Owner slightly slow: netem delay 20ms (below the deadline)",
    "e4": "Owner jittery around the deadline: netem delay 80ms +-40ms",
    "f": "Partial loss: netem loss 30%",
    "g": "Slow authority: 500 ms",
    "g2": "Very slow authority: 1200 ms (the owner needs > 1.2 s)",
    "h": "Mismatched peer lists (one node misses one peer)",
    "i": "Performance overhead (cache-hit throughput, miss-path latency)",
    "j": "Broken owner: answers probes but cannot resolve (its upstream is blackholed), resolve-ejection",
    "k": "All-slow upstream: authority delay 1200 ms, no resolve-ejection",
}

# ----------------------------------------------------------------- helpers
def sh(cmd, check=True, timeout=300, text=True):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=text, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError("command failed (%d): %s\n%s%s" % (p.returncode, cmd, p.stdout, p.stderr))
    return p.returncode, p.stdout + p.stderr


def pct(vals, p):
    if not vals:
        return float("nan")
    s = sorted(vals)
    k = min(len(s) - 1, max(0, int(round(p / 100.0 * len(s) + 0.5)) - 1))
    return s[k]


def lat_stats(rows):
    """rows: list of (t,target,qname,lat,rcode,an)"""
    n = len(rows)
    ok = [r[3] for r in rows if r[4] == 0]
    sf = sum(1 for r in rows if r[4] == 2)
    to = sum(1 for r in rows if r[4] == -1)
    other = sum(1 for r in rows if r[4] not in (0, 2, -1))
    return {"n": n, "p50": pct(ok, 50), "p95": pct(ok, 95), "p99": pct(ok, 99),
            "max": max(ok) if ok else float("nan"), "servfail": sf, "timeout": to,
            "other_err": other, "err_pct": 100.0 * (n - len(ok)) / n if n else 0.0}


def fmt(x, d=1):
    if isinstance(x, float):
        if x != x:
            return "-"
        return ("%." + str(d) + "f") % x
    return str(x)


def read_csv(path):
    rows = []
    with open(path) as f:
        r = csv.reader(f)
        next(r)
        for t, tg, qn, lat, rc, an in r:
            rows.append((float(t), tg, qn, float(lat), int(rc), int(an)))
    return rows


def ts_epoch(s):
    # docker -t timestamp 2026-11-07T12:00:00.123456789Z
    m = re.match(r"(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)(\.\d+)?Z", s)
    y, mo, d, h, mi, se = map(int, m.groups()[:6])
    frac = float(m.group(7) or 0)
    return datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone.utc).timestamp() + frac


# ----------------------------------------------------------------- context
class Ctx:
    def __init__(s, a):
        s.a = a
        s.N = a.nodes
        s.out = os.path.abspath(a.out)
        s.proj = a.project
        base = a.subnet.split("/")[0].rsplit(".", 1)[0]
        s.subnet = a.subnet
        s.auth_ip = base + ".2"
        s.lg_ip = base + ".3"
        s.ips = [base + "." + str(10 + i) for i in range(1, s.N + 1)]
        s.cn = ["%s-n%d" % (s.proj, i) for i in range(1, s.N + 1)]   # container names
        s.c_auth = s.proj + "-authority"
        s.c_lg = s.proj + "-loadgen"
        s.base_name = 1000      # fresh name allocator (names n<k>.test)
        s.results = []
        s.static_arp = False
        s.up_since = {}

    def fresh(self, n):
        b = self.base_name
        self.base_name += n + 10
        return b

    def node_dir(s, i):
        return os.path.join(s.out, "conf", "node%d" % (i + 1))

    def raw(s, sid):
        d = os.path.join(s.out, "raw", sid)
        os.makedirs(d, exist_ok=True)
        return d


def gen_conf(ctx, i, cluster=True, peers=None, extra_cluster="", threads=None):
    a = ctx.a
    peers = ctx.ips if peers is None else peers
    mod = "validator cluster iterator" if cluster else "validator iterator"
    c = """server:
    verbosity: 1
    use-syslog: no
    log-time-ascii: yes
    do-daemonize: no
    username: ""
    chroot: ""
    pidfile: ""
    directory: "/etc/unbound-node"
    interface: %s
    interface: 127.0.0.1
    port: 53
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    num-threads: %d
    msg-cache-size: 64m
    rrset-cache-size: 128m
    access-control: %s allow
    access-control: 127.0.0.0/8 allow
    module-config: "%s"
    domain-insecure: "test."
    local-zone: "test." nodefault
    do-not-query-localhost: no
    qname-minimisation: no
    prefetch: no
    ratelimit: 0
    ip-ratelimit: 0
    unwanted-reply-threshold: 0
    num-queries-per-thread: 4096
    outgoing-range: 4096
    so-rcvbuf: 4m
%s
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    control-use-cert: no

stub-zone:
    name: "test."
    stub-addr: %s
""" % (ctx.ips[i], threads or a.threads, ctx.subnet, mod, a.extra_server, ctx.auth_ip)
    if cluster:
        c += "\ncluster:\n"
        for p in peers:
            c += "    cluster-peer: %s\n" % p
        c += "    cluster-timeout: %d\n" % a.cluster_timeout
        if a.local_ttl_max:
            c += "    cluster-local-ttl-max: %d\n" % a.local_ttl_max
        c += extra_cluster
    return c


def write_confs(ctx, cluster=True, overrides=None, threads=None):
    overrides = overrides or {}
    for i in range(ctx.N):
        os.makedirs(ctx.node_dir(i), exist_ok=True)
        kw = overrides.get(i, {})
        with open(os.path.join(ctx.node_dir(i), "unbound.conf"), "w") as f:
            f.write(gen_conf(ctx, i, cluster=kw.get("cluster", cluster), peers=kw.get("peers"), threads=threads))


def gen_compose(ctx):
    a = ctx.a
    y = "name: %s\nnetworks:\n  net:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: %s\n" % (ctx.proj, ctx.subnet)
    y += "services:\n"
    y += """  authority:
    image: %(tools)s
    container_name: %(c)s
    command: ["python3", "/harness/authority.py"]
    environment: {ZONE: "test."}
    volumes: ["%(here)s:/harness:ro"]
    networks: {net: {ipv4_address: %(ip)s}}
""" % dict(tools=a.tools_image, c=ctx.c_auth, here=HERE, ip=ctx.auth_ip)
    y += """  loadgen:
    image: %(tools)s
    container_name: %(c)s
    volumes: ["%(here)s:/harness:ro", "%(res)s:/results"]
    cap_add: [NET_ADMIN]
    networks: {net: {ipv4_address: %(ip)s}}
""" % dict(tools=a.tools_image, c=ctx.c_lg, here=HERE, res=os.path.join(ctx.out, "results"), ip=ctx.lg_ip)
    for i in range(ctx.N):
        y += """  n%(k)d:
    image: %(img)s
    container_name: %(c)s
    cap_add: [NET_ADMIN]
    stop_grace_period: 3s
    volumes: ["%(conf)s:/etc/unbound-node"]
    networks: {net: {ipv4_address: %(ip)s}}
""" % dict(k=i + 1, img=a.unbound_image, c=ctx.cn[i], conf=ctx.node_dir(i), ip=ctx.ips[i])
    with open(os.path.join(ctx.out, "docker-compose.yml"), "w") as f:
        f.write(y)


def compose(ctx, *args, **kw):
    return sh(["docker", "compose", "-f", os.path.join(ctx.out, "docker-compose.yml"), "-p", ctx.proj] + list(args), **kw)


def pmap(fn, items, workers=16):
    with cf.ThreadPoolExecutor(workers) as ex:
        return list(ex.map(fn, items))


def dexec(ctx, cname, cmd, check=False, timeout=60):
    return sh(["docker", "exec", cname] + cmd, check=check, timeout=timeout)


def uc(ctx, i, *args, timeout=30):
    return dexec(ctx, ctx.cn[i], ["unbound-control", "-c", CONF] + list(args), timeout=timeout)


def ready(ctx, i, tries=60):
    for _ in range(tries):
        rc, out = uc(ctx, i, "status")
        if rc == 0:
            return True
        time.sleep(0.25)
    return False


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never use http_proxy for container IPs


def auth(ctx, path):
    with _OPENER.open("http://%s:8080%s" % (ctx.auth_ip, path), timeout=30) as r:
        return json.loads(r.read())


def parse_stats(txt):
    d = {}
    for l in txt.splitlines():
        if "=" in l:
            k, v = l.split("=", 1)
            try:
                d[k] = float(v)
            except ValueError:
                pass
    return d


def parse_status(txt):
    peers = {}
    info = {}
    for l in txt.splitlines():
        m = re.match(r"peer=(\S+) state=(\S+) fails=(\d+) .*routed=(\d+) answered=(\d+) failed=(\d+)", l)
        if m:
            ip = m.group(1).split("@")[0]
            peers[ip] = {"state": m.group(2), "fails": int(m.group(3)), "routed": int(m.group(4)),
                         "answered": int(m.group(5)), "failed": int(m.group(6)), "self": l.endswith(" self")}
            m2 = re.search(r"probe_ok=(\d+)% srtt=(\S+) res_ok=(\d+)% res_state=(\S+)", l)
            if m2:
                peers[ip].update({"probe_ok": int(m2.group(1)), "srtt": m2.group(2), "res_ok": int(m2.group(3)),
                                  "res_state": m2.group(4)})
        m = re.match(r"cache.msg.total=(\d+) cache.msg.owned=(\d+) cache.msg.nonowned=(\d+)", l)
        if m:
            info = {"total": int(m.group(1)), "owned": int(m.group(2)), "nonowned": int(m.group(3))}
    return peers, info


def collect_stats(ctx, nodes=None):
    nodes = list(range(ctx.N)) if nodes is None else nodes
    def one(i):
        rc, out = uc(ctx, i, "stats_noreset")
        return i, (parse_stats(out) if rc == 0 else {})
    return dict(pmap(one, nodes))


def sum_stats(st, keys_prefix=("cluster.", "num.", "total.")):
    t = {}
    for i, d in st.items():
        for k, v in d.items():
            if k.startswith(keys_prefix):
                t[k] = t.get(k, 0) + v
    return t


def collect_status(ctx, nodes=None):
    nodes = list(range(ctx.N)) if nodes is None else nodes
    def one(i):
        rc, out = uc(ctx, i, "cluster_status")
        return i, (parse_status(out) if rc == 0 else ({}, {}))
    return dict(pmap(one, nodes))


def node_logs(ctx, i, since):
    iso = datetime.datetime.fromtimestamp(since - 1, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rc, out = sh(["docker", "logs", "-t", "--since", iso, ctx.cn[i]], check=False)
    return out


def transitions(logs_by_node, victim_ip, since=0):
    """{node: [(t, 'up'|'down')]} for peer==victim_ip from node logs"""
    res = {}
    for i, txt in logs_by_node.items():
        ev = []
        for l in txt.splitlines():
            m = re.search(r"cluster: peer (\S+) is (up|down)", l)
            if m and m.group(1).split("@")[0] == victim_ip:
                t = ts_epoch(l.split(" ", 1)[0])
                if t >= since:
                    ev.append((t, m.group(2)))
        res[i] = ev
    return res


class Sampler(threading.Thread):
    """samples cluster_status on live nodes, records peer states over time"""
    def __init__(s, ctx, nodes, interval=1.0):
        super().__init__(daemon=True)
        s.ctx, s.nodes, s.interval, s.stop_ev = ctx, nodes, interval, threading.Event()
        s.samples = []  # (t, node, {ip: state})

    def run(s):
        def loop(i):
            while not s.stop_ev.is_set():
                t = time.time()
                rc, out = uc(s.ctx, i, "cluster_status", timeout=5)
                if rc == 0:
                    peers, _ = parse_status(out)
                    s.samples.append((t, i, {ip: p["state"] for ip, p in peers.items()}))
                s.stop_ev.wait(s.interval)
        ths = [threading.Thread(target=loop, args=(i,), daemon=True) for i in s.nodes]
        [t.start() for t in ths]
        [t.join() for t in ths]


# ----------------------------------------------------------------- lifecycle
def starts(ctx, i):
    rc, out = dexec(ctx, ctx.cn[i], ["sh", "-c", "wc -l < /tmp/starts"])
    try:
        return int(out.strip())
    except ValueError:
        return -1


def reset(ctx, cluster=True, overrides=None, auth_delay=0, ttl=3600, threads=None):
    """fresh caches and the wanted conf on all nodes: unbound is restarted inside the running
    containers (entry.sh supervisor), the containers/network namespaces/ARP state stay.
    Authority counters are reset."""
    def clean(i):
        sh(["docker", "unpause", ctx.cn[i]], check=False)
        rc, out = sh(["docker", "inspect", "-f", "{{.State.Running}}", ctx.cn[i]], check=False)
        if "true" not in out:
            sh(["docker", "start", ctx.cn[i]], check=False)
            time.sleep(1)
            if ctx.static_arp:
                static_neighbors(ctx)
        dexec(ctx, ctx.cn[i], ["tc", "qdisc", "del", "dev", "eth0", "root"])
        dexec(ctx, ctx.cn[i], ["rm", "-f", "/tmp/hold"])
    pmap(clean, range(ctx.N))
    write_confs(ctx, cluster, overrides, threads)
    before = pmap(lambda i: starts(ctx, i), range(ctx.N), 32)
    def restart(i):
        if before[i] < 1:       # container was just recreated, unbound is starting with the new conf anyway
            return
        dexec(ctx, ctx.cn[i], ["touch", "/tmp/restart"])
        uc(ctx, i, "stop")
    pmap(restart, range(ctx.N), 32)
    def wait(i):
        for _ in range(120):
            if starts(ctx, i) > before[i] and ready(ctx, i, 2):
                return True
            time.sleep(0.25)
        return False
    oks = pmap(wait, range(ctx.N), 32)
    if not all(oks):
        bad = [ctx.cn[i] for i, o in enumerate(oks) if not o]
        raise RuntimeError("unbound not ready: %s\n%s" % (bad, node_logs(ctx, ctx.cn.index(bad[0]), time.time() - 60)))
    auth(ctx, "/reset")
    auth(ctx, "/config?delay_ms=%s&ttl=%d&servfail=0" % (auth_delay, ttl))
    ctx.t_reset = time.time()


def static_neighbors(ctx):
    """Install permanent ARP entries for all containers in all containers.  Needed for big N on
    a busy docker host: if 40 containers resolve each other by ARP at the same time the burst of
    broadcasts overflows the host's softirq backlog, ARP exchanges are lost and the kernel drops
    the first packets to a neighbour while it is unresolved (seen as UDP SndbufErrors).  That
    shows up as bogus peer timeouts in the cluster module and peers marked down (it was the cause
    of the first failing 40-node runs).  Must be redone when a container is recreated or stopped
    and started (docker gives it a new MAC)."""
    net = "%s_net" % ctx.proj
    names = ctx.cn + [ctx.c_auth, ctx.c_lg]
    ips = ctx.ips + [ctx.auth_ip, ctx.lg_ip]
    def mac(c):
        rc, out = sh(["docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "%s").MacAddress}}' % net, c], check=False)
        return out.strip()
    macs = pmap(mac, names, 16)
    def install(k):
        lines = "".join("neigh replace %s lladdr %s dev eth0 nud permanent\n" % (ips[j], macs[j])
                        for j in range(len(names)) if j != k and macs[j])
        p = subprocess.run(["docker", "exec", "-i", names[k], "ip", "-batch", "-"], input=lines, capture_output=True, text=True)
        return p.returncode == 0
    res = pmap(install, range(len(names)), 8)
    print("  static neighbour entries installed (%d/%d containers)%s" % (sum(res), len(res),
          "" if all(res) else ", failed: " + ",".join(names[k] for k, r in enumerate(res) if not r)), flush=True)


def loadgen_cmd(ctx, name, args):
    return ["docker", "exec", ctx.c_lg, "python3", "/harness/loadgen.py", "--out", "/results/%s.csv" % name] + [str(x) for x in args]


def loadgen(ctx, name, args, bg=False):
    cmd = loadgen_cmd(ctx, name, args)
    if bg:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rc, out = sh(cmd, check=True, timeout=1200)
    return read_csv(os.path.join(ctx.out, "results", name + ".csv"))


def lg_wait(ctx, p, name):
    out, _ = p.communicate()
    if p.returncode != 0:
        raise RuntimeError("loadgen failed: " + out)
    return read_csv(os.path.join(ctx.out, "results", name + ".csv"))


def targets_arg(ctx, exclude=()):
    return ",".join(ctx.ips[i] for i in range(ctx.N) if i not in exclude)


def save_raw(ctx, sid, name, obj):
    with open(os.path.join(ctx.raw(sid), name), "w") as f:
        json.dump(obj, f, indent=1, default=str)


def crash_check(ctx, expect_restarts=None):
    """containers where unbound exited unexpectedly (entry.sh logs those in /tmp/crashes)"""
    def one(i):
        rc, out = dexec(ctx, ctx.cn[i], ["sh", "-c", "cat /tmp/crashes 2>/dev/null"])
        return i, out.strip()
    return [(ctx.cn[i], out) for i, out in pmap(one, range(ctx.N)) if out]


def apply_stats(res, st, keys):
    s = sum_stats(st)
    res["stats"] = {k: s.get(k, 0) for k in keys}
    return s


CL_KEYS = ["cluster.routed", "cluster.answered", "cluster.answered.cachehit", "cluster.probe.miss",
           "cluster.failed", "cluster.timeout", "cluster.resolve_timeout", "cluster.fallback", "cluster.charged",
           "cluster.resolve_ejected", "cluster.self", "cluster.excluded",
           "cluster.nolive", "cluster.served", "cluster.served.probe_miss", "cluster.version_mismatch",
           "total.num.queries", "total.num.cachehits", "total.num.cachemiss"]


def check(res, desc, ok, detail=""):
    res["checks"].append({"desc": desc, "pass": bool(ok), "detail": detail})


# Scenarios that report numbers only: their checks are shown as INFO and never count as pass/fail.
# f: step 2 (the request to the owner to resolve) is sent over UDP and is never sent again (decision of
# 2026-11-08, cluster-design.md section 7): a lost step 2 packet costs that query the full step 2 deadline
# before the local fallback, so under 30% packet loss some queries are slow by design.  The cluster is
# intended for (nearly) lossless LANs.
INFORMATIONAL = {
    "f": "informational, not pass/fail: step 2 is sent over UDP without retransmission (decision in "
         "cluster-design.md section 7), so a lost packet costs the query the full step 2 deadline "
         "before the local fallback; the cluster is intended for near-lossless LANs",
}


def new_res(sid):
    return {"id": sid, "title": TITLES[sid], "checks": [], "notes": [], "tables": [], "metrics": {},
            "informational": INFORMATIONAL.get(sid)}


def check_label(x, c):
    if x.get("informational"):
        return "INFO ok" if c["pass"] else "INFO outside"
    return "PASS" if c["pass"] else "**FAIL**"


def auth_per_name(ctx, prefix_base=None):
    s = auth(ctx, "/summary")
    return s


# ----------------------------------------------------------------- scenarios
def sc_a(ctx):
    a = ctx.a
    res = new_res("a")
    K, N = a.names, ctx.N
    rounds = a.rounds or 4 * N
    rows_t = []
    for mode in ("nocluster", "cluster"):
        reset(ctx, cluster=(mode == "cluster"))
        base = ctx.fresh(K)
        t0 = time.time()
        rows = loadgen(ctx, "a_%s" % mode, ["--mode", "pool", "--targets", targets_arg(ctx), "--base", base,
                                              "--count", K, "--rounds", rounds, "--rate", a.rate, "--seed", 7])
        summ = auth(ctx, "/summary")
        st = collect_stats(ctx)
        s = sum_stats(st)
        status = collect_status(ctx) if mode == "cluster" else {}
        owned = sum(v[1].get("owned", 0) for v in status.values())
        nonowned = sum(v[1].get("nonowned", 0) for v in status.values())
        total = sum(v[1].get("total", 0) for v in status.values())
        ls = lat_stats(rows)
        m = {"mode": mode, "queries": len(rows), "names": K, "rounds": rounds, "lat": ls,
             "auth_total": summ["total_queries"], "auth_raw_per_name": summ["raw_per_name_mean"],
             "auth_src_per_name": summ["src_per_name_mean"], "src_hist": summ["src_hist"],
             "raw_hist": summ["raw_hist"], "stats": {k: s.get(k, 0) for k in CL_KEYS},
             "cache_msg_total": total, "cache_msg_owned": owned, "cache_msg_nonowned": nonowned,
             "crash": crash_check(ctx)}
        res["metrics"][mode] = m
        save_raw(ctx, "a", mode + "_summary.json", {"auth": summ, "stats": st, "status": status})
        shutil.copy(os.path.join(ctx.out, "results", "a_%s.csv" % mode), ctx.raw("a"))
    nc, cl = res["metrics"]["nocluster"], res["metrics"]["cluster"]
    check(res, "baseline: each node fetches (distinct source nodes per name ~N, >= 0.8N)",
          nc["auth_src_per_name"] >= 0.8 * N, "%.2f per name (N=%d)" % (nc["auth_src_per_name"], N))
    check(res, "cluster: authority sees ~1 distinct node per name (<= 1.05)", cl["auth_src_per_name"] <= 1.05,
          "%.3f distinct nodes, %.3f raw queries per name" % (cl["auth_src_per_name"], cl["auth_raw_per_name"]))
    check(res, "cluster: no name fetched from 3+ nodes", all(int(k) <= 2 for k in cl["src_hist"]), str(cl["src_hist"]))
    check(res, "no SERVFAIL / timeouts in either run", cl["lat"]["err_pct"] == 0 and nc["lat"]["err_pct"] == 0,
          "cluster %.2f%%, baseline %.2f%%" % (cl["lat"]["err_pct"], nc["lat"]["err_pct"]))
    check(res, "no unbound crash/restart", not cl["crash"] and not nc["crash"], str(cl["crash"] + nc["crash"]))
    res["metrics"]["reduction"] = nc["auth_total"] / max(1, cl["auth_total"])
    return res


def sc_b(ctx):
    a = ctx.a
    res = new_res("b")
    K = a.names
    for mode in ("nocluster", "cluster"):
        reset(ctx, cluster=(mode == "cluster"))
        base = ctx.fresh(K)
        # K bursts, 20 bursts/s; each burst: one fresh name to ALL nodes at once
        rows = loadgen(ctx, "b_%s" % mode, ["--mode", "stream", "--targets", targets_arg(ctx), "--base", base,
                                              "--rate", 20, "--duration", K / 20.0, "--fanout", ctx.N, "--seed", 3])
        summ = auth(ctx, "/summary")
        st = collect_stats(ctx)
        s = sum_stats(st)
        res["metrics"][mode] = {"lat": lat_stats(rows), "auth_total": summ["total_queries"],
                                "auth_raw_per_name": summ["raw_per_name_mean"],
                                "auth_src_per_name": summ["src_per_name_mean"], "src_hist": summ["src_hist"],
                                "raw_hist": summ["raw_hist"], "stats": {k: s.get(k, 0) for k in CL_KEYS},
                                "crash": crash_check(ctx)}
        save_raw(ctx, "b", mode + "_summary.json", {"auth": summ, "stats": st})
        shutil.copy(os.path.join(ctx.out, "results", "b_%s.csv" % mode), ctx.raw("b"))
    # diagnosis run: same herd with 1 worker thread per node (herd protection is per worker thread)
    reset(ctx, cluster=True, threads=1)
    K2 = min(K, 200)
    base = ctx.fresh(K2)
    rows = loadgen(ctx, "b_1thread", ["--mode", "stream", "--targets", targets_arg(ctx), "--base", base, "--rate", 20,
                                        "--duration", K2 / 20.0, "--fanout", ctx.N, "--seed", 3])
    summ = auth(ctx, "/summary")
    st = collect_stats(ctx)
    s = sum_stats(st)
    res["metrics"]["cluster_1thread"] = {"lat": lat_stats(rows), "auth_total": summ["total_queries"],
                                         "auth_raw_per_name": summ["raw_per_name_mean"], "auth_src_per_name": summ["src_per_name_mean"],
                                         "src_hist": summ["src_hist"], "raw_hist": summ["raw_hist"],
                                         "stats": {k: s.get(k, 0) for k in CL_KEYS}, "crash": crash_check(ctx)}
    shutil.copy(os.path.join(ctx.out, "results", "b_1thread.csv"), ctx.raw("b"))
    cl = res["metrics"]["cluster"]
    nc = res["metrics"]["nocluster"]
    t1 = res["metrics"]["cluster_1thread"]
    check(res, "herd, num-threads=1: authority sees exactly ~1 query per name (<= 1.05)",
          t1["auth_raw_per_name"] <= 1.05, "%.3f raw per name; hist %s" % (t1["auth_raw_per_name"], t1["raw_hist"]))
    check(res, "herd, num-threads=%d: only ONE node fetches each name (distinct nodes/name <= 1.05)" % ctx.a.threads,
          cl["auth_src_per_name"] <= 1.05, "%.3f distinct nodes/name" % cl["auth_src_per_name"])
    res["notes"].append("With num-threads=%d the owner resolves a herd name once PER WORKER THREAD (raw/name %.2f vs %.2f with 1 thread): "
                        "unbound's mesh (and hence the R2 peer-state merge) is per thread, the incoming peer queries are spread over "
                        "threads by SO_REUSEPORT, so up to num-threads upstream queries per name from the owner. Not a cross-node duplicate."
                        % (ctx.a.threads, cl["auth_raw_per_name"], t1["auth_raw_per_name"]))
    check(res, "herd, default threads: authority raw queries per name <= num-threads x 1.05 (see note)", cl["auth_raw_per_name"] <= ctx.a.threads * 1.05,
          "%.3f raw / %.3f distinct nodes per name; hist %s" % (cl["auth_raw_per_name"], cl["auth_src_per_name"], cl["raw_hist"]))
    check(res, "reference: without cluster ~N per name", nc["auth_raw_per_name"] >= 0.9 * ctx.N,
          "%.2f per name" % nc["auth_raw_per_name"])
    check(res, "no SERVFAIL / timeouts", cl["lat"]["err_pct"] == 0, "%.2f%%" % cl["lat"]["err_pct"])
    check(res, "no unbound crash/restart", not cl["crash"], str(cl["crash"]))
    return res


def windows(rows, edges, names):
    out = []
    for k in range(len(names)):
        lo, hi = edges[k], edges[k + 1]
        sub = [r for r in rows if lo <= r[0] < hi]
        d = lat_stats(sub)
        d["window"] = names[k]
        d["secs"] = hi - lo
        out.append(d)
    return out


def fail_scenario(ctx, sid, inject, remove, victim, t_inj, t_rem, t_end, kind, expect_restarts=None,
                  fanout=1, rate=None, auth_delay=0, client_timeout=3.0, cluster_overrides=None,
                  settle=None):
    """generic: stream of fresh names with one node impaired between t_inj..t_rem"""
    a = ctx.a
    res = new_res(sid)
    reset(ctx, cluster=True, overrides=cluster_overrides, auth_delay=auth_delay)
    rate = rate or a.fail_rate
    live = [i for i in range(ctx.N) if i != victim]
    sampler = Sampler(ctx, live, 1.0)
    sampler.start()
    base = ctx.fresh(int(t_end * rate) * fanout)
    t_launch = time.time()
    p = loadgen(ctx, "%s_run" % sid, ["--mode", "stream", "--targets", targets_arg(ctx, [victim]), "--base", base,
                                        "--rate", rate, "--duration", t_end, "--fanout", fanout,
                                        "--timeout", client_timeout, "--seed", 11], bg=True)
    time.sleep(max(0, t_launch + t_inj - time.time()))
    ev1 = time.time()
    inject()
    if t_rem is not None:
        time.sleep(max(0, t_launch + t_rem - time.time()))
        ev2 = time.time()
        remove()
    else:
        ev2 = None
    rows = lg_wait(ctx, p, "%s_run" % sid)
    t_fin = time.time()
    sampler.stop_ev.set()
    sampler.join(timeout=10)
    if ev2 is None:
        ev2 = t_fin + 1
    # windows
    t_start = rows[0][0] if rows else ev1
    t_stop = rows[-1][0] + 0.001 if rows else ev2
    edges = [t_start, ev1, min(ev1 + 5, ev2), ev2, ev2 + 10, t_stop + 1]
    names = ["before", "inject+0..5s", "impaired(steady)", "after removal 0..10s", "recovered (10s+)"]
    # fix: window 'impaired' is [ev1+5, ev2)
    edges = [t_start, ev1, ev1 + 5, ev2, ev2 + 10, t_stop + 1]
    wins = windows(rows, edges, names)
    allw = lat_stats(rows)
    st = collect_stats(ctx)
    s = sum_stats(st)
    ids = {i: node_logs(ctx, i, ctx.t_reset) for i in range(ctx.N)}
    victim_ip = ctx.ips[victim]
    tr = transitions({i: ids[i] for i in live}, victim_ip, ctx.t_reset)
    summ = auth(ctx, "/summary")
    status = collect_status(ctx)
    res["metrics"] = {"victim": ctx.cn[victim], "inject_at": ev1 - t_launch, "remove_at": (ev2 - t_launch) if t_rem else None,
                      "overall": allw, "windows": wins, "stats": {k: s.get(k, 0) for k in CL_KEYS},
                      "auth_raw_per_name": summ["raw_per_name_mean"], "auth_src_per_name": summ["src_per_name_mean"],
                      "raw_hist": summ["raw_hist"], "src_hist": summ["src_hist"], "kind": kind}
    # transitions relative to events
    det, rec, nflaps = [], [], {}
    for i, evs in tr.items():
        downs = [t for t, k in evs if k == "down"]
        ups = [t for t, k in evs if k == "up"]
        nflaps[ctx.cn[i]] = {"down": len(downs), "up": len(ups)}
        d1 = [t - ev1 for t in downs if t >= ev1]
        det.append(min(d1) if d1 else None)
        if t_rem is not None:
            u1 = [t - ev2 for t in ups if t >= ev2]
            rec.append(min(u1) if u1 else None)
    res["metrics"]["during"] = {ctx.cn[i]: {"down": sum(1 for t, k in evs if k == "down" and ev1 <= t < ev2),
                                            "up": sum(1 for t, k in evs if k == "up" and ev1 <= t < ev2)} for i, evs in tr.items()}
    res["metrics"]["detect_s"] = det
    res["metrics"]["recover_s"] = rec
    res["metrics"]["transitions"] = nflaps
    # sampled transitions
    sflap = {}
    for i in live:
        seq = [(t, st_[victim_ip]) for t, n, st_ in sorted(sampler.samples) if n == i and victim_ip in st_]
        ch = sum(1 for k in range(1, len(seq)) if (seq[k][1] == "up") != (seq[k - 1][1] == "up"))
        sflap[ctx.cn[i]] = ch
    res["metrics"]["sampled_state_changes"] = sflap
    res["metrics"]["final_victim_state"] = {ctx.cn[i]: status[i][0].get(victim_ip, {}).get("state") for i in live}
    crash = crash_check(ctx, expect_restarts)
    res["metrics"]["crash"] = crash
    save_raw(ctx, sid, "stats.json", {"stats": st, "status": status, "transitions": tr, "samples": sampler.samples, "auth": summ,
                                      "events": {"launch": t_launch, "inject": ev1, "remove": ev2}})
    for i in range(ctx.N):
        with open(os.path.join(ctx.raw(sid), "unbound-n%d.log" % (i + 1)), "w") as f:
            f.write(ids[i])
    shutil.copy(os.path.join(ctx.out, "results", "%s_run.csv" % sid), ctx.raw(sid))
    check(res, "no unbound crash/restart (/tmp/starts)", not crash, str(crash))
    return res, wins, tr, ev1, ev2


def fmin(l):
    l = [x for x in l if x is not None]
    return (min(l), max(l)) if l else (None, None)


def sc_c(ctx):
    v = ctx.N - 1
    a = ctx.a
    res, wins, tr, ev1, ev2 = fail_scenario(
        ctx, "c", lambda: sh(["docker", "stop", "-t", "1", ctx.cn[v]], check=False),
        lambda: (sh(["docker", "start", ctx.cn[v]], check=False), static_neighbors(ctx) if ctx.static_arp else None), v, 8, 22, 60, "stop",
        expect_restarts={v: 1})
    generic_fail_checks(ctx, res, v, max_detect=10, max_recover=45, max_steady_p99=60, max_inject_max=FALLBACK_MAX_MS)
    return res


def sc_c2(ctx):
    v = ctx.N - 1
    def kill():
        dexec(ctx, ctx.cn[v], ["touch", "/tmp/hold"])
        uc(ctx, v, "stop")
    res, wins, tr, ev1, ev2 = fail_scenario(
        ctx, "c2", kill, lambda: dexec(ctx, ctx.cn[v], ["rm", "-f", "/tmp/hold"]), v, 8, 22, 60, "proc",
        expect_restarts={v: 2})
    generic_fail_checks(ctx, res, v, max_detect=10, max_recover=45, max_steady_p99=60, max_inject_max=FALLBACK_MAX_MS)
    rows = read_csv(os.path.join(ctx.out, "results", "c2_run.csv"))
    ev = res["metrics"]["inject_at"]
    t0 = rows[0][0]
    win = [r for r in rows if t0 + ev <= r[0] < t0 + ev + 3]
    slow = sum(1 for r in win if r[3] >= 90)
    res["metrics"]["slow_after_inject"] = slow
    # Unbound ignores ICMP port unreachable on UDP (documented limitation), so a closed port is
    # detected like a silent peer: by the probe deadline (cluster-timeout).  Until the peer is marked
    # down (3 failed probes AND no reply for CLUSTER_ALIVE_WINDOW = 1 s) every query owned by the
    # victim waits the full deadline, then falls back.  Bound: victim-owned queries in
    # window + 3 deadlines, with 25% margin; and no single query is slower than the deadline + 100 ms.
    to = ctx.a.cluster_timeout / 1000.0
    bound = int(ctx.a.fail_rate / ctx.N * (1.0 + 3 * to + 0.6) * 1.25) + 1
    slowmax = max([r[3] for r in win] or [0])
    check(res, "ICMP port unreachable is not seen (documented limitation): detection bounded by the deadline: <= %d queries wait the full deadline in the 3 s after the kill" % bound,
          slow <= bound, "%d queries took >= 90 ms" % slow)
    check(res, "no query waits longer than cluster-timeout + 100 ms in the 3 s after the kill", slowmax <= ctx.a.cluster_timeout + 100,
          "max %.0f ms" % slowmax)
    return res


def sc_d(ctx):
    v = ctx.N - 1
    res, wins, tr, ev1, ev2 = fail_scenario(
        ctx, "d", lambda: sh(["docker", "pause", ctx.cn[v]], check=False),
        lambda: sh(["docker", "unpause", ctx.cn[v]], check=False), v, 8, 28, 80, "pause", expect_restarts={v: 1})
    generic_fail_checks(ctx, res, v, max_detect=10, max_recover=45, max_steady_p99=60, max_inject_max=FALLBACK_MAX_MS)
    return res


def netem(ctx, v, spec):
    def inj():
        rc, out = dexec(ctx, ctx.cn[v], ["tc", "qdisc", "add", "dev", "eth0", "root", "netem"] + spec.split())
        if rc != 0:
            raise RuntimeError("tc failed: " + out)
    return inj


def netem_del(ctx, v, drain=False):
    """remove the netem qdisc.  Deleting a qdisc throws away the packets that are queued in it for delay; with
    UDP and no retransmission of the request to resolve (step 2) such a packet is lost for good and costs the
    query its deadline.  That is an artefact of the removal, not of the impairment, so for delay specs
    (drain=True) the delay is set to 0 first and the queue is given time to empty."""
    def rm():
        if drain:
            dexec(ctx, ctx.cn[v], ["tc", "qdisc", "change", "dev", "eth0", "root", "netem", "delay", "0ms"])
            time.sleep(0.5)
        return dexec(ctx, ctx.cn[v], ["tc", "qdisc", "del", "dev", "eth0", "root"])
    return rm


def sc_d2(ctx):
    v = ctx.N - 1
    res, wins, tr, ev1, ev2 = fail_scenario(ctx, "d2", netem(ctx, v, "loss 100%"), netem_del(ctx, v), v, 8, 28, 80, "netem")
    generic_fail_checks(ctx, res, v, max_detect=10, max_recover=45, max_steady_p99=60, max_inject_max=FALLBACK_MAX_MS)
    return res


def sc_e(ctx, sid="e", spec="delay 200ms", mode="down"):
    v = ctx.N - 1
    res, wins, tr, ev1, ev2 = fail_scenario(ctx, sid, netem(ctx, v, spec), netem_del(ctx, v, drain=True), v, 8, 38, 60, "netem")
    m = res["metrics"]
    st = m["stats"]
    t = m["transitions"]
    downs = [x["down"] for x in t.values()]
    ups = [x["up"] for x in t.values()]
    check(res, "no SERVFAIL / client timeouts", m["overall"]["servfail"] + m["overall"]["timeout"] == 0,
          "%d servfail, %d timeouts of %d" % (m["overall"]["servfail"], m["overall"]["timeout"], m["overall"]["n"]))
    if mode == "up":
        check(res, "peer stays up on every node (no transitions)", sum(downs) + sum(ups) == 0,
              "down transitions %s, up %s" % (downs, ups))
        # The reply latency of a jittery peer has a tail: a probe reply that takes longer than the
        # cluster-timeout deadline falls back by design (cluster.timeout).  Allowed: at most 0.2% of the
        # routed queries, and every failure must be such a deadline expiry (no error, no outnet cut,
        # no bad answer).  The health state must not change (checked above).
        routed = max(1, st["cluster.routed"])
        check(res, "fallbacks only from the probe deadline (jitter tail): all failures are deadline expiries, <= 0.2% of routed",
              st["cluster.failed"] == st["cluster.timeout"] and st["cluster.fallback"] <= 0.002 * routed,
              "fallback=%d timeout=%d failed=%d resolve_timeout=%d of %d routed (%.3f%%)"
              % (st["cluster.fallback"], st["cluster.timeout"], st["cluster.failed"],
                 st.get("cluster.resolve_timeout", 0), routed, 100.0 * st["cluster.fallback"] / routed))
    elif mode == "down":
        check(res, "no flapping while impaired: <=1 down and 0 up per node between inject and removal",
              all(x["down"] <= 1 and x["up"] == 0 for x in m["during"].values()),
              "during impairment: %s; whole run: %s" % (m["during"], t))
        check(res, "slow peer detected (marked down on all live nodes)", all(d is not None for d in m["detect_s"]),
              "detect_s=%s" % [fmt(x) for x in m["detect_s"]])
        check(res, "bounded latency: max <= 1000 ms", m["overall"]["max"] <= 1000, "max %.0f ms" % m["overall"]["max"])
    else:  # info
        check(res, "latency bounded: max <= 1000 ms", m["overall"]["max"] <= 1000, "max %.0f ms" % m["overall"]["max"])
        res["notes"].append("informational scenario: transitions per node %s; fallback=%d failed=%d timeout=%d"
                            % (t, st["cluster.fallback"], st["cluster.failed"], st["cluster.timeout"]))
    return res


def sc_e2(ctx):
    return sc_e(ctx, "e2", "delay 50ms 40ms", "up")


def sc_e3(ctx):
    return sc_e(ctx, "e3", "delay 20ms", "up")


def sc_e4(ctx):
    return sc_e(ctx, "e4", "delay 80ms 40ms", "info")


def sc_f(ctx):
    v = ctx.N - 1
    res, wins, tr, ev1, ev2 = fail_scenario(ctx, "f", netem(ctx, v, "loss 30%"), netem_del(ctx, v), v, 8, 48, 70, "netem")
    m = res["metrics"]
    st = m["stats"]
    downs = {k: x["down"] for k, x in m["during"].items()}
    ups = {k: x["up"] for k, x in m["during"].items()}
    check(res, "no SERVFAIL / client timeouts", m["overall"]["servfail"] + m["overall"]["timeout"] == 0,
          "%d servfail, %d timeouts" % (m["overall"]["servfail"], m["overall"]["timeout"]))
    check(res, "bounded latency: max <= 1000 ms", m["overall"]["max"] <= 1000, "max %.0f ms" % m["overall"]["max"])
    check(res, "state stable (hysteresis): <= 2 up/down transitions per node in the 40 s impaired window",
          all(downs[k] + ups[k] <= 2 for k in downs), "down %s up %s" % (downs, ups))
    m["fallback_rate"] = st["cluster.fallback"] / max(1, st["cluster.routed"])
    return res


# A query that is in the resolve step (step 2) when the owner dies waits for the step 2 deadline (the
# discard budget of the client, 1900 ms by default, at most CLUSTER_RESOLVE_MAX 3 s, cluster/cluster.h;
# it is not cut short by the outnet timeout) and is then resolved locally: bound = deadline + 100 ms.
# (The reply of the local resolution is then past discard-timeout, UDP clients retry.)
FALLBACK_MAX_MS = 1600


def generic_fail_checks(ctx, res, v, max_detect, max_recover, max_steady_p99, max_inject_max):
    m = res["metrics"]
    o = m["overall"]
    check(res, "no SERVFAIL / client timeouts", o["servfail"] + o["timeout"] == 0,
          "%d servfail, %d timeouts of %d queries" % (o["servfail"], o["timeout"], o["n"]))
    dm = [d for d in m["detect_s"]]
    check(res, "owner marked down by every live node within %ds of injection" % max_detect,
          all(d is not None and d <= max_detect for d in dm), "detect times [s]: %s" % [fmt(x, 2) for x in dm])
    w = {x["window"]: x for x in m["windows"]}
    check(res, "latency bounded by fallback: max <= %d ms in every window" % max_inject_max,
          o["max"] <= max_inject_max, "max %.0f ms; window maxima %s" % (o["max"], [fmt(x["max"], 0) for x in m["windows"]]))
    st = w.get("impaired(steady)")
    if st and st["n"]:
        check(res, "steady down state: p99 <= %d ms (no per-query penalty once marked down)" % max_steady_p99,
              st["p99"] <= max_steady_p99, "p99 %.1f ms, p50 %.1f ms" % (st["p99"], st["p50"]))
    if m["recover_s"]:
        rc = m["recover_s"]
        check(res, "owner back up on every live node within %ds of recovery" % max_recover,
              all(r is not None and r <= max_recover for r in rc), "recover times [s]: %s" % [fmt(x, 1) for x in rc])
    check(res, "no flapping: each live node logs exactly 1 down + 1 up", all(x["down"] == 1 and x["up"] == 1 for x in m["transitions"].values()),
          str(m["transitions"]))


def warm_infra(ctx, sid, cluster, delay):
    """Warm the infra cache (RTT/RTO) of every node before a slow-authority measurement, the same
    way with and without the cluster.  Unbound learns the RTT of the authority per node; on a cold
    start against a 1.2 s authority every query of the first ~1.13 s (376 + 752 ms UDP timeouts)
    misses the 1.9 s discard budget.  Without the cluster every node starts learning at t=0, with
    the cluster a node starts only when it first resolves a name it owns, so the cold-start window
    is longer by the arrival time of that name (verified against per-query data: predicted =
    observed failures).  That is a start-up transient, not the steady state the g/g2/k checks are
    about.  Phase 1: every node resolves one name itself (owned by it with the cluster); phase 2
    (cluster): every node asks every other node to resolve a fresh name it owns (the step 2
    entry).  The authority counters and the unbound statistics are reset afterwards."""
    per = {}
    def names(j):
        out, k = [], 0
        while len(out) < ctx.N and k < 500:
            nm = "warm%d-%d.w.%s." % (j, k, "test")
            k += 1
            if cluster:
                rc, o = uc(ctx, j, "cluster_lookup", nm)
                if "owned=yes" not in o:
                    continue
            out.append(nm)
        return out
    got = pmap(names, range(ctx.N))
    for j in range(ctx.N):
        per[j] = got[j]
    ph1 = ["%s %s" % (ctx.ips[j], per[j][0]) for j in range(ctx.N) if per[j]]
    ph2 = []
    for j in range(ctx.N):
        others = [i for i in range(ctx.N) if i != j]
        for i, nm in zip(others, per[j][1:]):
            ph2.append("%s %s" % (ctx.ips[i], nm))
    for ph, lines in (("1", ph1), ("2", ph2)):
        if not lines:
            continue
        with open(os.path.join(ctx.out, "results", "%s_warm%s.txt" % (sid, ph)), "w") as f:
            f.write("\n".join(lines) + "\n")
        loadgen(ctx, "%s_warm%s" % (sid, ph), ["--mode", "list", "--file", "/results/%s_warm%s.txt" % (sid, ph),
                                               "--concurrency", len(lines), "--timeout", 8])
    pmap(lambda i: uc(ctx, i, "stats"), range(ctx.N))   # reset the counters
    auth(ctx, "/reset")
    auth(ctx, "/config?delay_ms=%s&ttl=%d&servfail=0" % (delay, 3600))


def sc_g(ctx, sid="g", delay=500, expect_fallback=False):
    a = ctx.a
    res = new_res(sid)
    reset(ctx, cluster=True, auth_delay=delay)
    warm_infra(ctx, sid, True, delay)
    N = ctx.N
    K = 300 if delay <= 500 else 120
    fan = min(3, N)
    base = ctx.fresh(K * fan)
    dur = K / 10.0
    sampler = Sampler(ctx, list(range(N)), 1.0)
    sampler.start()
    t0 = time.time()
    rows = loadgen(ctx, "%s_run" % sid, ["--mode", "stream", "--targets", targets_arg(ctx), "--base", base, "--rate", 10,
                                           "--duration", dur, "--fanout", fan, "--timeout", 8, "--seed", 5])
    time.sleep(1)
    sampler.stop_ev.set(); sampler.join(timeout=10)
    summ = auth(ctx, "/summary")
    st = collect_stats(ctx)
    s = sum_stats(st)
    logs = {i: node_logs(ctx, i, ctx.t_reset) for i in range(N)}
    downs = {}
    ejects = 0
    for i in range(N):
        downs[ctx.cn[i]] = sum(1 for l in logs[i].splitlines() if re.search(r"cluster: peer \S+ is down", l))
        ejects += sum(1 for l in logs[i].splitlines() if re.search(r"cluster: peer \S+ is resolve-ejected", l))
    states = {}
    for t, n, d in sampler.samples:
        for ip, sname in d.items():
            states[sname] = states.get(sname, 0) + 1
    ls = lat_stats(rows)
    res["metrics"] = {"lat": ls, "auth_raw_per_name": summ["raw_per_name_mean"], "auth_src_per_name": summ["src_per_name_mean"],
                      "raw_hist": summ["raw_hist"], "src_hist": summ["src_hist"], "stats": {k: s.get(k, 0) for k in CL_KEYS},
                      "down_log_lines": downs, "sampled_peer_states": states, "auth_delay_ms": delay, "fanout": fan,
                      "crash": crash_check(ctx)}
    save_raw(ctx, sid, "stats.json", {"stats": st, "auth": summ, "samples": sampler.samples})
    for i in range(N):
        with open(os.path.join(ctx.raw(sid), "unbound-n%d.log" % (i + 1)), "w") as f:
            f.write(logs[i])
    shutil.copy(os.path.join(ctx.out, "results", "%s_run.csv" % sid), ctx.raw(sid))
    check(res, "no peer ever marked down (no 'is down' log, all samples 'up')",
          sum(downs.values()) == 0 and set(states) <= {"up"}, "down log lines %s; sampled states %s" % (sum(downs.values()), states))
    # a slow upstream is slow for everyone: the failures of the owner are not charged because the local
    # fallback is slow too, nobody is resolve-ejected
    check(res, "no peer resolve-ejected (no 'resolve-ejected' log, cluster.resolve_ejected 0)",
          ejects == 0 and s.get("cluster.resolve_ejected", 0) == 0,
          "log lines %d; resolve_ejected=%d charged=%d fallback=%d" % (ejects, s.get("cluster.resolve_ejected", 0),
                                                                        s.get("cluster.charged", 0), s.get("cluster.fallback", 0)))
    if not expect_fallback:
        check(res, "no SERVFAIL / client timeouts", ls["servfail"] + ls["timeout"] == 0, "%d / %d" % (ls["servfail"], ls["timeout"]))
    if not expect_fallback:
        check(res, "upstream: ~1 distinct node per name at the authority (<= 1.05)", summ["src_per_name_mean"] <= 1.05,
              "%.3f distinct nodes, %.3f raw per name (raw>1 can be unbound UDP retransmits to the slow authority)" % (summ["src_per_name_mean"], summ["raw_per_name_mean"]))
        check(res, "no fallbacks / probe timeouts", s.get("cluster.fallback", 0) == 0 and s.get("cluster.timeout", 0) == 0,
              "fallback=%d timeout=%d failed=%d" % (s.get("cluster.fallback", 0), s.get("cluster.timeout", 0), s.get("cluster.failed", 0)))
        check(res, "latency ~ authority delay (p50 >= delay, sanity)", ls["p50"] >= delay, "p50 %.0f ms" % ls["p50"])
    else:
        res["notes"].append("Resolve deadline (discard budget, 1.9 s) is near the authority delay plus the unbound retries: requesters fall back to local resolution and so fetch themselves; "
                            "this is the designed behaviour, informational only: fallback=%d, distinct nodes/name %.2f"
                            % (s.get("cluster.fallback", 0), summ["src_per_name_mean"]))
    check(res, "no unbound crash/restart", not res["metrics"]["crash"], str(res["metrics"]["crash"]))
    res["notes"].append("Both runs start after an infra warm-up (every node has resolved via the authority, and with the "
                        "cluster has sent a step 2 to every peer), see warm_infra: the cold-start RTT learning is per node "
                        "and the cluster delays it by the arrival of the first owned name, a start-up transient")
    # reference: same workload with the cluster module off
    reset(ctx, cluster=False, auth_delay=delay)
    warm_infra(ctx, sid + "_ref", False, delay)
    rows_ref = loadgen(ctx, "%s_ref_nocluster" % sid, ["--mode", "stream", "--targets", targets_arg(ctx), "--base", ctx.fresh(K * fan), "--rate", 10,
                                                       "--duration", dur, "--fanout", fan, "--timeout", 8, "--seed", 5])
    summ_ref = auth(ctx, "/summary")
    res["metrics"]["ref_nocluster"] = {"lat": lat_stats(rows_ref), "auth_raw_per_name": summ_ref["raw_per_name_mean"],
                                       "auth_src_per_name": summ_ref["src_per_name_mean"]}
    if expect_fallback:
        rt = res["metrics"]["ref_nocluster"]["lat"]["timeout"] + res["metrics"]["ref_nocluster"]["lat"]["servfail"]
        check(res, "client timeouts/SERVFAIL not worse than the cluster-off reference (%d)" % rt,
              ls["servfail"] + ls["timeout"] <= rt, "cluster %d vs reference %d" % (ls["servfail"] + ls["timeout"], rt))
    # evidence: one herd name with verbose logging on all nodes
    reset(ctx, cluster=True, auth_delay=delay)
    for i in range(N):
        uc(ctx, i, "verbosity", "4")
    t_ev = time.time()
    loadgen(ctx, "%s_evidence" % sid, ["--mode", "stream", "--targets", targets_arg(ctx), "--base", ctx.fresh(1), "--rate", 1,
                                         "--duration", 1, "--fanout", fan, "--timeout", 8])
    with open(os.path.join(ctx.raw(sid), "evidence_verbose.log"), "w") as f:
        for i in range(N):
            f.write("===== %s\n" % ctx.cn[i])
            for l in node_logs(ctx, i, t_ev).splitlines():
                if re.search(r"cluster:|serviced query UDP timeout|timeout udp|sending to target|query response was timeout", l):
                    f.write(l + "\n")
    for i in range(N):
        uc(ctx, i, "verbosity", "1")
    res["notes"].append("verbose single-name evidence: raw/%s/evidence_verbose.log" % sid)
    return res


def sc_g2(ctx):
    return sc_g(ctx, "g2", 1200, True)


def sc_k(ctx):
    """all-slow upstream: the same workload as g2 under another name, with the resolution health
    checks (nobody is resolve-ejected, clients are not worse off than without the cluster)"""
    return sc_g(ctx, "k", 1200, True)


def sc_j(ctx):
    """broken owner: the victim runs fine and answers cache probes, but cannot reach the authority
    (egress to the authority is dropped with tc, a silent upstream).  Step 2 requests to it fail at the
    deadline, the local fallback resolves fast, so the failures are charged and the victim is
    resolve-ejected by every other node; it is never marked down (probes are answered)."""
    v = ctx.N - 1
    cmds = [["tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "prio"],
            ["tc", "filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", "1", "u32",
             "match", "ip", "dst", ctx.auth_ip + "/32", "action", "drop"]]
    def inj():
        for c in cmds:
            rc, out = dexec(ctx, ctx.cn[v], c)
            if rc != 0:
                raise RuntimeError("tc failed: " + out)
    t_inj, t_rem, t_end = 8, 40, 110
    res, wins, tr, ev1, ev2 = fail_scenario(ctx, "j", inj, netem_del(ctx, v), v, t_inj, t_rem, t_end,
                                            "tc drop of the egress to the authority")
    m = res["metrics"]
    st = m["stats"]
    live = [i for i in range(ctx.N) if i != v]
    vip = ctx.ips[v]
    logs = {i: node_logs(ctx, i, ctx.t_reset) for i in live}
    first_eject, again = {}, {}
    n_eject = {}
    for i in live:
        for l in logs[i].splitlines():
            mm = re.search(r"cluster: peer (\S+) is resolve-ejected", l)
            if mm and mm.group(1).split("@")[0] == vip:
                t = ts_epoch(l.split(" ", 1)[0])
                if t >= ev1:
                    first_eject.setdefault(i, t - ev1)
                    n_eject[i] = n_eject.get(i, 0) + 1
            mm = re.search(r"cluster: peer (\S+) resolves again", l)
            if mm and mm.group(1).split("@")[0] == vip:
                t = ts_epoch(l.split(" ", 1)[0])
                if t >= ev2 and i not in again:
                    again[i] = t - ev2
    status = collect_status(ctx, live)
    final = {ctx.cn[i]: status[i][0].get(vip, {}).get("res_state") for i in live}
    m["resolve_eject_s"] = [first_eject.get(i) for i in live]
    m["resolve_again_s"] = [again.get(i) for i in live]
    m["ejections_per_node"] = {ctx.cn[i]: n_eject.get(i, 0) for i in live}
    m["final_res_state"] = final
    for i in live:
        with open(os.path.join(ctx.raw("j"), "unbound-n%d.log" % (i + 1)), "w") as f:
            f.write(logs[i])
    o = m["overall"]
    w = {x["window"]: x for x in m["windows"]}
    check(res, "victim never marked down (it answers probes): 0 down transitions on every live node",
          all(x["down"] == 0 for x in m["transitions"].values()), str(m["transitions"]))
    ej = m["resolve_eject_s"]
    check(res, "victim resolve-ejected by every live node within 8 s of the injection",
          all(x is not None and x <= 8 for x in ej), "eject times [s]: %s" % [fmt(x, 1) for x in ej])
    others = sum(1 for i in live for l in logs[i].splitlines() if "resolve-ejected" in l and vip not in l)
    check(res, "only the victim is ever resolve-ejected (no 'resolve-ejected' line for another peer)", others == 0,
          "%d lines" % others)
    first = w.get("inject+0..5s")
    exp = ctx.a.fail_rate / ctx.N          # queries per second for names that the victim owns
    err_first = (first["servfail"] + first["timeout"]) if first else 0
    check(res, "client impact bounded while the nodes learn (first 5 s): errors <= 5 s x rate/N = %d" % int(5 * exp),
          err_first <= 5 * exp, "%d errors (SERVFAIL + timeouts) of %d queries" % (err_first, first["n"] if first else 0))
    steady = w.get("impaired(steady)")
    err_steady = (steady["servfail"] + steady["timeout"]) if steady else 0
    check(res, "ejected steady state: errors <= 3 per live node (the trial requests, 10/20/30 s apart)",
          err_steady <= 3 * len(live), "%d errors in %.0f s; p99 %.1f ms, p50 %.1f ms" % (
              err_steady, steady["secs"] if steady else 0, steady["p99"] if steady else 0, steady["p50"] if steady else 0))
    if steady and steady["n"]:
        check(res, "ejected steady state: p99 <= 60 ms (no per-query penalty)", steady["p99"] <= 60,
              "p99 %.1f ms" % steady["p99"])
    check(res, "counters: charged >= 3 per live node, resolve_ejected > 0 (misses resolved locally without asking)",
          st["cluster.charged"] >= 3 * len(live) and st["cluster.resolve_ejected"] > 0,
          "charged=%d resolve_ejected=%d fallback=%d resolve_timeout=%d" % (
              st["cluster.charged"], st["cluster.resolve_ejected"], st["cluster.fallback"], st["cluster.resolve_timeout"]))
    ag = m["resolve_again_s"]
    check(res, "after the fix the victim resolves again on every live node within 45 s of the removal",
          all(x is not None and x <= 45 for x in ag), "recover times [s]: %s" % [fmt(x, 1) for x in ag])
    check(res, "final res_state of the victim is ok on every live node", all(v_ == "ok" for v_ in final.values()), str(final))
    return res


def sc_h(ctx):
    a = ctx.a
    res = new_res("h")
    N = ctx.N
    miss = N - 1                       # peer missing from node 0's list
    peers0 = [ip for k, ip in enumerate(ctx.ips) if k != miss]
    results = {}
    for mode, ov in (("consistent", None), ("mismatched", {0: {"peers": peers0}})):
        reset(ctx, cluster=True, overrides=ov, threads=1)
        K = a.names
        base = ctx.fresh(K)
        rows = loadgen(ctx, "h_%s" % mode, ["--mode", "stream", "--targets", targets_arg(ctx), "--base", base, "--rate", 20,
                                              "--duration", K / 20.0, "--fanout", N, "--seed", 9])
        summ = auth(ctx, "/summary")
        st = collect_stats(ctx)
        s = sum_stats(st)
        results[mode] = {"lat": lat_stats(rows), "auth_total": summ["total_queries"], "auth_raw_per_name": summ["raw_per_name_mean"],
                         "auth_src_per_name": summ["src_per_name_mean"], "raw_hist": summ["raw_hist"], "src_hist": summ["src_hist"],
                         "stats": {k: s.get(k, 0) for k in CL_KEYS}, "crash": crash_check(ctx),
                         "per_node_served": {ctx.cn[i]: st[i].get("cluster.served", 0) for i in range(N)},
                         "per_node_routed": {ctx.cn[i]: st[i].get("cluster.routed", 0) for i in range(N)}}
        save_raw(ctx, "h", mode + "_stats.json", {"stats": st, "auth": summ})
        shutil.copy(os.path.join(ctx.out, "results", "h_%s.csv" % mode), ctx.raw("h"))
    res["metrics"] = results
    mm, cs = results["mismatched"], results["consistent"]
    check(res, "no SERVFAIL / timeouts with mismatched lists", mm["lat"]["err_pct"] == 0, "%.2f%%" % mm["lat"]["err_pct"])
    check(res, "no query storm: authority total <= 2.5 x names (extra hop only)", mm["auth_total"] <= 2.5 * a.names,
          "%d queries for %d names; consistent run: %d" % (mm["auth_total"], a.names, cs["auth_total"]))
    check(res, "no name fetched from more than 2 nodes", all(int(k) <= 2 for k in mm["src_hist"]), str(mm["src_hist"]))
    check(res, "latency not pathological: p99 <= 500 ms", mm["lat"]["p99"] <= 500, "p99 %.0f ms (consistent %.0f)" % (mm["lat"]["p99"], cs["lat"]["p99"]))
    check(res, "no unbound crash/restart", not mm["crash"] and not cs["crash"], str(mm["crash"] + cs["crash"]))
    return res


def dnsperf(ctx, target, secs, nfile):
    rc, out = dexec(ctx, ctx.c_lg, ["dnsperf", "-s", target, "-p", "53", "-d", nfile, "-l", str(secs), "-c", "8", "-q", "400",
                                   "-T", str(ctx.a.perf_threads), "-t", "2"], timeout=secs + 60)
    m = re.search(r"Queries per second:\s+([\d.]+)", out)
    lost = re.search(r"Queries lost:\s+(\d+)", out)
    lat = re.search(r"Average Latency \(s\):\s+([\d.]+) \(min ([\d.]+), max ([\d.]+)\)", out)
    return {"qps": float(m.group(1)) if m else float("nan"), "lost": int(lost.group(1)) if lost else -1,
            "avg_lat_ms": float(lat.group(1)) * 1000 if lat else float("nan"), "raw": out}


def sc_i(ctx):
    a = ctx.a
    res = new_res("i")
    N = ctx.N
    # --- throughput of cache hits on node 1
    K = 2000
    qf = os.path.join(ctx.out, "results", "perf_names.txt")
    with open(qf, "w") as f:
        for k in range(K):
            f.write("n%d.test A\n" % (500000 + k))
    reps = a.perf_reps
    tp = {"nocluster": [], "cluster": []}
    for rep in range(reps):
        for mode in (("nocluster", "cluster") if rep % 2 == 0 else ("cluster", "nocluster")):
            reset(ctx, cluster=(mode == "cluster"))
            loadgen(ctx, "i_warm_%s" % mode, ["--mode", "pool", "--targets", ctx.ips[0], "--base", 500000, "--count", K,
                                                "--rounds", 1, "--rate", 1500])
            r = dnsperf(ctx, ctx.ips[0], a.perf_secs, "/results/perf_names.txt")
            st = collect_stats(ctx, [0])
            r["cachehits"] = st[0].get("total.num.cachehits", 0)
            r["cachemiss"] = st[0].get("total.num.cachemiss", 0)
            tp[mode].append(r)
            with open(os.path.join(ctx.raw("i"), "dnsperf_%s_%d.txt" % (mode, rep)), "w") as f:
                f.write(r["raw"])
    for mode in tp:
        for r in tp[mode]:
            r.pop("raw", None)
    mean = lambda l: statistics.mean(l) if l else float("nan")
    res["metrics"]["throughput"] = tp
    qn = mean([r["qps"] for r in tp["nocluster"]])
    qc = mean([r["qps"] for r in tp["cluster"]])
    res["metrics"]["throughput_mean"] = {"nocluster": qn, "cluster": qc, "ratio": qc / qn if qn else float("nan")}
    check(res, "cache-hit throughput with cluster module >= 90% of without", qc >= 0.9 * qn,
          "%.0f vs %.0f qps (ratio %.3f; host is shared and noisy, see README)" % (qc, qn, qc / qn if qn else 0))
    check(res, "dnsperf runs measured cache hits (miss count small)", all(r["cachemiss"] <= K * 1.5 for m in tp.values() for r in m),
          str([r["cachemiss"] for m in tp.values() for r in m]))
    # --- miss path latency
    delay = a.miss_auth_delay
    reset(ctx, cluster=True, auth_delay=delay)
    base = ctx.fresh(1200)
    cands = ["n%d.test." % (base + k) for k in range(a.miss_names * 4)]
    def owner_of(nm):
        rc, out = uc(ctx, 0, "cluster_lookup", nm)
        m = re.search(r"rank=1 peer=(\S+?)@", out)
        return nm, (m.group(1) if m else None)
    own = dict(pmap(owner_of, cands, 12))
    selfn = [n for n in cands if own[n] == ctx.ips[0]]
    other = [n for n in cands if own[n] and own[n] != ctx.ips[0]]
    M = a.miss_names
    S, B, C = selfn[:M], other[:M], other[M:2 * M]
    def lst(path, pairs):
        with open(os.path.join(ctx.out, "results", path), "w") as f:
            for tgt, nm in pairs:
                f.write("%s %s\n" % (tgt, nm))
    # prime owners for B
    lst("i_prime.txt", [(own[n], n) for n in B])
    loadgen(ctx, "i_prime", ["--mode", "list", "--file", "/results/i_prime.txt", "--concurrency", 4])
    lst("i_hit.txt", [(ctx.ips[0], n) for n in B])
    hit = loadgen(ctx, "i_ownerhit", ["--mode", "list", "--file", "/results/i_hit.txt", "--concurrency", 1])
    hit2 = loadgen(ctx, "i_localhit", ["--mode", "list", "--file", "/results/i_hit.txt", "--concurrency", 1])
    lst("i_miss.txt", [(ctx.ips[0], n) for n in C])
    omiss = loadgen(ctx, "i_ownermiss", ["--mode", "list", "--file", "/results/i_miss.txt", "--concurrency", 1])
    lst("i_self.txt", [(ctx.ips[0], n) for n in S])
    selfm = loadgen(ctx, "i_selfmiss", ["--mode", "list", "--file", "/results/i_self.txt", "--concurrency", 1])
    st = collect_stats(ctx)
    s = sum_stats(st)
    summ_auth = auth(ctx, "/summary")
    # baseline: no cluster, local miss
    reset(ctx, cluster=False, auth_delay=delay)
    D = ["n%d.test." % (base + 800 + k) for k in range(M)]
    lst("i_base.txt", [(ctx.ips[0], n) for n in D])
    basem = loadgen(ctx, "i_basemiss", ["--mode", "list", "--file", "/results/i_base.txt", "--concurrency", 1])
    L = {"nocluster local miss": lat_stats(basem), "cluster, self-owned miss": lat_stats(selfm),
         "cluster, owner miss (probe MISS + resolve at owner)": lat_stats(omiss),
         "cluster, owner-cache hit (probe HIT)": lat_stats(hit), "local msg-cache hit (reference)": lat_stats(hit2)}
    res["metrics"]["miss_latency"] = L
    res["metrics"]["miss_auth_delay_ms"] = delay
    res["metrics"]["miss_sets"] = {"self": len(S), "owner-hit": len(B), "owner-miss": len(C)}
    res["metrics"]["miss_stats"] = {k: s.get(k, 0) for k in CL_KEYS}
    add_probe = L["cluster, owner miss (probe MISS + resolve at owner)"]["p50"] - L["cluster, self-owned miss"]["p50"]
    res["metrics"]["probe_overhead_p50_ms"] = add_probe
    check(res, "owner-miss adds <= 10 ms p50 over a self-owned miss (extra LAN round trips)", add_probe <= 10, "%.2f ms" % add_probe)
    check(res, "owner-cache hit is faster than a local miss (p50)", L["cluster, owner-cache hit (probe HIT)"]["p50"] < L["nocluster local miss"]["p50"],
          "%.2f vs %.2f ms" % (L["cluster, owner-cache hit (probe HIT)"]["p50"], L["nocluster local miss"]["p50"]))
    check(res, "miss-path run had no errors", all(v["err_pct"] == 0 for v in L.values()), str({k: v["err_pct"] for k, v in L.items()}))
    check(res, "authority saw each cluster-mode name once", summ_auth["raw_per_name_mean"] <= 1.05, "%.3f" % summ_auth["raw_per_name_mean"])
    return res


SC = {"a": sc_a, "b": sc_b, "c": sc_c, "c2": sc_c2, "d": sc_d, "d2": sc_d2, "e": sc_e, "e2": sc_e2, "e3": sc_e3,
      "e4": sc_e4, "f": sc_f, "g": sc_g, "g2": sc_g2, "h": sc_h, "i": sc_i, "j": sc_j, "k": sc_k}


# ----------------------------------------------------------------- report
def table(headers, rows):
    s = "| " + " | ".join(headers) + " |\n|" + "|".join("---" for _ in headers) + "|\n"
    for r in rows:
        s += "| " + " | ".join(str(x) for x in r) + " |\n"
    return s + "\n"


def lat_row(label, d):
    return [label, d["n"], fmt(d["p50"], 2), fmt(d["p95"], 1), fmt(d["p99"], 1), fmt(d["max"], 0), d["servfail"], d["timeout"]]


LH = ["window", "queries", "p50 ms", "p95 ms", "p99 ms", "max ms", "SERVFAIL", "timeouts"]


def render(ctx, results, meta):
    r = "# Cluster compose harness report\n\n"
    r += "- Generated: %s\n- Source tree: `%s` (%s)\n- Nodes: %d, threads/node: %d, cluster-timeout: %d ms\n- Subnet: %s\n- Host: %s\n\n" % (
        meta["date"], meta["src"], meta["rev"], ctx.N, ctx.a.threads, ctx.a.cluster_timeout, ctx.subnet, meta["host"])
    r += "Command: `%s`\n\n" % meta["cmd"]
    r += "## Summary\n\n"
    rows = []
    for x in results:
        p = sum(1 for c in x["checks"] if c["pass"])
        if x.get("informational"):
            rows.append([x["id"], x["title"] + " (informational)", "%d/%d within bound" % (p, len(x["checks"])), "INFO"])
        else:
            rows.append([x["id"], x["title"], "%d/%d" % (p, len(x["checks"])), "PASS" if p == len(x["checks"]) else "**FAIL**"])
    r += table(["id", "scenario", "checks passed", "result"], rows)
    for x in results:
        if x.get("informational"):
            r += "Scenario %s is %s.\n\n" % (x["id"], x["informational"])
    for x in results:
        r += "## %s: %s\n\n" % (x["id"], x["title"])
        m = x["metrics"]
        try:
            r += render_one(ctx, x, m)
        except Exception as e:
            r += "(metrics not rendered: %r)\n\n" % e
        r += "Checks:\n\n" + table(["", "check", "detail"], [[check_label(x, c), c["desc"], c["detail"]] for c in x["checks"]])
        for n in x["notes"]:
            r += "Note: %s\n\n" % n
    return r


def render_one(ctx, x, m):
    r = ""
    if True:
        sid = x["id"]
        if sid == "a" or sid == "b" or sid == "h":
            modes = ["nocluster", "cluster"] if sid != "h" else ["consistent", "mismatched"]
            if sid == "b":
                modes.append("cluster_1thread")
            rr = []
            for md in modes:
                d = m[md]
                rr.append([md, d["lat"]["n"], fmt(d["lat"]["p50"], 2), fmt(d["lat"]["p95"], 1), fmt(d["lat"]["p99"], 1), fmt(d["lat"]["max"], 0),
                           "%.2f%%" % d["lat"]["err_pct"], d["auth_total"], "%.3f" % d["auth_raw_per_name"], "%.3f" % d["auth_src_per_name"],
                           d["raw_hist"]])
            r += table(["mode", "queries", "p50", "p95", "p99", "max (ms)", "errors", "authority queries", "raw/name", "distinct nodes/name", "raw-count histogram"], rr)
            if sid == "a":
                c = m["cluster"]
                r += "Authority-query reduction cluster vs baseline: **%.2fx**. msg-cache entries over all nodes (cluster): total %d, owned %d, non-owned %d (K=%d names).\n\n" % (
                    m["reduction"], c["cache_msg_total"], c["cache_msg_owned"], c["cache_msg_nonowned"], c["names"])
            for md in modes:
                if md in ("cluster", "mismatched", "cluster_1thread"):
                    r += "Counters (sum over nodes, %s): `%s`\n\n" % (md, {k: int(v) for k, v in m[md]["stats"].items()})
            if sid == "h":
                r += "Per-node cluster.served (mismatched): `%s`\n\n" % m["mismatched"]["per_node_served"]
        elif sid in ("g", "g2", "k"):
            r += table(LH, [lat_row("cluster", m["lat"])] + ([lat_row("reference, cluster off", m["ref_nocluster"]["lat"])] if "ref_nocluster" in m else []))
            r += "Authority delay %d ms, fanout %d; authority raw/name %.3f, distinct nodes/name %.3f, raw hist %s. Sampled peer states: %s. Counters: `%s`\n\n" % (
                m["auth_delay_ms"], m["fanout"], m["auth_raw_per_name"], m["auth_src_per_name"], m["raw_hist"], m["sampled_peer_states"],
                {k: int(v) for k, v in m["stats"].items()})
        elif sid == "i":
            tm = m["throughput_mean"]
            r += "Cache-hit throughput on node 1 (dnsperf, %d runs each, mean): no-cluster **%.0f qps**, cluster **%.0f qps** (ratio %.3f).\n\n" % (
                ctx.a.perf_reps, tm["nocluster"], tm["cluster"], tm["ratio"])
            r += table(["run", "mode", "qps", "avg latency ms", "lost"], [[k + 1, md, "%.0f" % q["qps"], "%.2f" % q["avg_lat_ms"], q["lost"]]
                                                                     for md in m["throughput"] for k, q in enumerate(m["throughput"][md])])
            r += "Miss-path latency (authority delay %s ms, sequential client, node 1; sets %s):\n\n" % (m["miss_auth_delay_ms"], m["miss_sets"])
            r += table(["case"] + LH[1:], [lat_row(k, v) for k, v in m["miss_latency"].items()])
            r += "Probe overhead (owner miss minus self-owned miss, p50): %.2f ms. Counters: `%s`\n\n" % (m["probe_overhead_p50_ms"], {k: int(v) for k, v in m["miss_stats"].items()})
        else:
            r += "Impairment `%s` on %s at t=%.1fs%s.\n\n" % (m["kind"], m["victim"], m["inject_at"],
                                                              (", removed at t=%.1fs" % m["remove_at"]) if m["remove_at"] else "")
            r += table(LH, [lat_row("%s (%.0fs)" % (w["window"], w["secs"]), w) for w in m["windows"]] + [lat_row("overall", m["overall"])])
            r += "Detection time (impairment -> peer logged down) per live node [s]: `%s`; recovery (removal -> logged up) [s]: `%s`.\n\n" % (
                [fmt(v, 2) for v in m["detect_s"]], [fmt(v, 1) for v in m["recover_s"]])
            r += "Up/down transitions of the victim in node logs: `%s`; state changes seen by 1 Hz `cluster_status` sampling: `%s`; final state: `%s`.\n\n" % (
                m["transitions"], m["sampled_state_changes"], m["final_victim_state"])
            r += "Counters (sum over live nodes): `%s`. Authority: %.3f raw/name, %.3f distinct nodes/name.\n\n" % (
                {k: int(v) for k, v in m["stats"].items()}, m["auth_raw_per_name"], m["auth_src_per_name"])
            if "resolve_eject_s" in m:
                r += ("Resolve-ejection of the victim: first ejection per live node after the injection [s]: `%s`; ejections per node: `%s`; "
                      "\"resolves again\" after the removal [s]: `%s`; final res_state: `%s`.\n\n" % (
                          [fmt(v, 1) for v in m["resolve_eject_s"]], m["ejections_per_node"],
                          [fmt(v, 1) for v in m["resolve_again_s"]], m["final_res_state"]))
    return r


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default=os.path.abspath(os.path.join(HERE, "..", "..")), help="unbound source tree (default: repo root)")
    ap.add_argument("--out", default=os.path.join(HERE, "results", "run"), help="output directory (conf, raw data, report)")
    ap.add_argument("--nodes", type=int, default=5)
    ap.add_argument("--threads", type=int, default=2, help="unbound num-threads per node")
    ap.add_argument("--scenarios", default="all", help="comma list of: " + ",".join(ALL))
    ap.add_argument("--project", default="ucc")
    ap.add_argument("--subnet", default="10.231.0.0/24")
    ap.add_argument("--unbound-image", default="ucc-unbound:local")
    ap.add_argument("--tools-image", default="ucc-tools:local")
    ap.add_argument("--static-arp", default="auto", choices=["auto", "yes", "no"],
                    help="permanent ARP entries between containers (auto: when N > 10)")
    ap.add_argument("--no-build", action="store_true", help="do not (re)build images")
    ap.add_argument("--keep", action="store_true", help="leave containers/network running at the end")
    ap.add_argument("--names", type=int, default=500, help="K distinct names for scenarios a, b, h")
    ap.add_argument("--rounds", type=int, default=0, help="scenario a: queries per name (default 4*N)")
    ap.add_argument("--rate", type=float, default=1500, help="scenario a: client qps")
    ap.add_argument("--fail-rate", type=float, default=200, help="failure scenarios: fresh names (queries) per second")
    ap.add_argument("--cluster-timeout", type=int, default=100)
    ap.add_argument("--local-ttl-max", type=int, default=0)
    ap.add_argument("--extra-server", default="", help="extra raw lines for the server: section of every node")
    ap.add_argument("--perf-secs", type=int, default=10)
    ap.add_argument("--perf-reps", type=int, default=3)
    ap.add_argument("--perf-threads", type=int, default=2, help="dnsperf -T")
    ap.add_argument("--miss-names", type=int, default=150)
    ap.add_argument("--miss-auth-delay", type=int, default=20, help="authority delay (ms) for the miss-path latency test")
    a = ap.parse_args()
    a.src = os.path.abspath(a.src)
    ctx = Ctx(a)
    sel = ALL if a.scenarios == "all" else a.scenarios.split(",")
    for s in sel:
        if s not in SC:
            sys.exit("unknown scenario " + s)
    os.makedirs(os.path.join(ctx.out, "results"), exist_ok=True)
    if not a.no_build:
        print("building images from", a.src, flush=True)
        sh(["docker", "build", "--build-context", "src=" + a.src, "-f", os.path.join(HERE, "Dockerfile.unbound"),
            "-t", a.unbound_image, HERE], timeout=3600)
        sh(["docker", "build", "-f", os.path.join(HERE, "Dockerfile.tools"), "-t", a.tools_image, HERE], timeout=1800)
    write_confs(ctx, True)
    gen_compose(ctx)
    meta = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "src": a.src, "cmd": " ".join(sys.argv),
            "rev": "unknown", "host": "%d cpus, %s" % (os.cpu_count(), sh("uname -r")[1].strip())}
    rc, out = sh("cd %s && git rev-parse --short HEAD 2>/dev/null" % a.src, check=False)
    if rc == 0 and out.strip():
        meta["rev"] = "git " + out.strip()
    try:
        print("starting", ctx.N, "nodes", flush=True)
        compose(ctx, "up", "-d", "--force-recreate", timeout=600)
        time.sleep(2)
        if a.static_arp == "yes" or (a.static_arp == "auto" and ctx.N > 10):
            ctx.static_arp = True
            static_neighbors(ctx)
        for _ in range(40):
            try:
                auth(ctx, "/summary"); break
            except Exception:
                time.sleep(0.5)
        rc, out = dexec(ctx, ctx.cn[0], ["unbound", "-V"])
        meta["unbound"] = out.splitlines()[0:3]
        rc, out = dexec(ctx, ctx.cn[0], ["sh", "-c", "tc qdisc add dev eth0 root netem delay 1ms && tc qdisc del dev eth0 root && echo tc-ok"])
        if "tc-ok" not in out:
            print("WARNING: tc netem not usable in containers:", out, flush=True)
        results = []
        for s in sel:
            print("=== scenario", s, TITLES[s], flush=True)
            t = time.time()
            try:
                x = SC[s](ctx)
            except Exception as e:
                import traceback
                x = new_res(s)
                x["checks"].append({"desc": "scenario ran to completion", "pass": False, "detail": "HARNESS ERROR: %r" % e})
                x["notes"].append("harness exception: " + traceback.format_exc())
                print(traceback.format_exc(), flush=True)
            x["elapsed_s"] = time.time() - t
            results.append(x)
            for c in x["checks"]:
                print("  %s %s -- %s" % (("INFO-ok" if c["pass"] else "INFO-outside") if x.get("informational") else
                                          ("PASS" if c["pass"] else "FAIL"), c["desc"], c["detail"]), flush=True)
            with open(os.path.join(ctx.out, "results.json"), "w") as f:
                json.dump({"meta": meta, "results": results}, f, indent=1, default=str)
            with open(os.path.join(ctx.out, "report.md"), "w") as f:
                f.write(render(ctx, results, meta))
        print("report:", os.path.join(ctx.out, "report.md"))
    finally:
        if not a.keep:
            sh(["docker", "exec", ctx.c_lg, "chmod", "-R", "a+rwX", "/results"], check=False)
            compose(ctx, "down", "-v", "--remove-orphans", timeout=300)
    return 0


if __name__ == "__main__":
    sys.exit(main())
