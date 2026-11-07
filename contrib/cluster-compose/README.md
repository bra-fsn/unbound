# cluster-compose: multi-instance test and benchmark harness for the unbound `cluster` module

Runs N unbound containers (built from source with `--enable-cluster`), a fake
authoritative server and a load generator on one docker bridge network and
drives failure / performance scenarios against them.  The output is a markdown
report with a table per scenario, pass/fail checks against the expectations of
`cluster-design.md` (sections 2, 7, 9, 11), and the raw data.

## Requirements

- Docker with the compose plugin (tested: Docker 29, compose v5), BuildKit
  (for `--build-context`), internet access for the image builds (apt, pip).
- Linux host: the harness reaches the authority's HTTP stats port on the
  container IP directly, and `tc netem` needs the `sch_netem` kernel module.
  The containers get `NET_ADMIN`; nothing needs `--privileged`.
- Host python3 (stdlib only).  Subnet `10.231.0.0/24` must be free
  (`--subnet`).  About 40 MB of RAM per node.

## Files

| file | purpose |
|---|---|
| `harness.py` | driver: builds images, generates compose + per-node configs, runs scenarios, writes `report.md`, `results.json`, raw data |
| `Dockerfile.unbound`, `entry.sh` | multi-stage build of unbound with `--enable-cluster`; runtime has `iproute2` (tc) and `unbound-control`; `entry.sh` is a supervisor: a planned restart (`/tmp/restart`, used by the scenario resets) or a stopped unbound (`/tmp/hold`, scenario c2) keeps the container, its network namespace, IP and MAC; an unexpected exit is logged in `/tmp/crashes` and reported as a crash |
| `Dockerfile.tools` | python + dnspython + dnsperf + iproute2, used for the authority and the load generator |
| `authority.py` | fake authority for `test.`: `n0..n999999.test. A`, wildcard `*.w.test.`, NXDOMAIN otherwise; runtime TTL and per-query delay; counts queries per qname and source; HTTP stats on :8080 |
| `loadgen.py` | async UDP client (stdlib only), modes `pool`, `stream`, `list`, `sched`; per-query CSV (time, target node, qname, latency, rcode) |

The nodes use the authority as the only upstream via
`stub-zone: name: "test." stub-addr: <authority>`; the zone `test.` is
`local-zone: nodefault` (unbound has a built-in empty `test.` zone) and
`domain-insecure: "test."`.  Each node has the same config except
`interface:`, lists all nodes as `cluster-peer:` (self detected from the
`interface:` address), `module-config: "validator cluster iterator"`
(`"validator iterator"` for the baselines), `access-control` for the subnet,
remote control on 127.0.0.1:8953 without certificates.

## Running

```
cd contrib/cluster-compose
# everything, N=5, source = this repo root (two levels up), output in ./results/run
python3 harness.py

# another source tree (e.g. a frozen snapshot), custom output directory
python3 harness.py --src /path/to/unbound --out /tmp/ucc-run

# only some scenarios; 40 nodes steady state baseline-vs-cluster
python3 harness.py --src /path/to/unbound --nodes 40 --scenarios a,b --names 200 --out /tmp/ucc-run40

# reuse already built images, leave containers running for poking around
python3 harness.py --no-build --keep --scenarios a
docker exec ucc-n1 unbound-control -c /etc/unbound-node/unbound.conf cluster_status
curl -s 10.231.0.2:8080/summary
```

Containers are removed at the end (`docker compose down -v`) unless `--keep`.
Images (`ucc-unbound:local`, `ucc-tools:local`) are left in place.

Options: `--src --out --nodes --threads` (unbound threads per node, default 2)
`--scenarios` (comma list of `a b c c2 d d2 e e2 e3 e4 f g g2 h i j k`)
`--project` (compose project and container prefix, default `ucc`)
`--subnet --names --rounds --rate --fail-rate --cluster-timeout --local-ttl-max`
`--extra-server` (raw lines appended to `server:`, e.g. `verbosity: 4`)
`--perf-secs --perf-reps --perf-threads --miss-names --miss-auth-delay`
`--no-build --keep`.

## Scenarios

| id | what | state reset |
|---|---|---|
| a | K names queried (4N times each) from random nodes, cluster off vs on; authority queries per name | all unbound containers restarted (cold caches), authority counters reset, per run |
| b | thundering herd: each fresh name asked from all nodes at the same instant, cluster off/on, plus a 1-thread diagnosis run | same |
| c | `docker stop` the owner at t=8s, `docker start` at t=22s | |
| c2 | owner process stopped (`unbound-control stop`), container up: ICMP port unreachable (ignored by unbound, so detected like a silent peer: bounded by `cluster-timeout`, not instant), then restarted | |
| d | `docker pause` the owner, then unpause | |
| d2 | `tc netem loss 100%` on the owner's eth0, then removed | |
| e / e2 / e3 / e4 | `netem delay` 200ms / 50ms+-40ms / 20ms / 80ms+-40ms on the owner | |
| f | `netem loss 30%` on the owner for 40 s.  **Informational**: the numbers are reported, the checks are labelled INFO and do not count as pass/fail, because step 2 (the request to the owner to resolve) is sent over UDP without retransmission (spec decision in `cluster-design.md` section 7): a lost step 2 packet costs that query the full step 2 deadline before the local fallback, the cluster is intended for near-lossless LANs | |
| g / g2 | authority delay 500 ms / 1200 ms, herd of 3 nodes per name; no peer marked down, none resolve-ejected; g2: clients not worse off than with the cluster off | both runs (cluster and reference) start after an infra warm-up (`warm_infra`): unbound learns the authority RTT per node, and with the cluster a node starts learning only at its first owned name, a cold-start transient that is not the steady state checked here |
| h | node 1 has a peer list missing one peer, herd workload | |
| i | dnsperf cache-hit throughput on node 1 (cluster on/off, interleaved runs) and miss-path latency (self-owned, owner miss, owner hit, no cluster) with a 20 ms authority | |
| j | broken owner (health model v2): the victim answers cache probes but cannot resolve, its egress to the authority is dropped with `tc` (u32 filter, `action drop`); fresh names are streamed to the other nodes.  Expected: every other node resolve-ejects the victim within a few seconds (3 charged failures: the step 2 request runs into its deadline, the local fallback resolves fast), never marks it down, steady-state clients are not penalised (names of the victim are resolved locally), and the victim resolves again after the removal (trial request) | |
| k | all-slow upstream: the same as g2 (authority delay 1200 ms, a herd of 3 nodes per name), with the resolution health checks: no peer is resolve-ejected (the local fallback is slow too, so the failures of the owner are not charged), clients not worse off than the cluster-off reference | |

Failure scenarios (c..f) stream fresh names (so every query is a cache miss
that has to be routed) from all nodes except the impaired one ("victim", the
last node) at `--fail-rate` qps, and compute latency windows before / during /
after, detection and recovery time (from the nodes' `peer X is down/up` log
lines, timestamped by docker), and 1 Hz `cluster_status` samples.  netem is
applied to the victim's egress only, so it delays the victim's replies and
also its queries to the authority.  Every scenario also checks `/tmp/starts`
in each container to detect unbound crashes/restarts.

The pass/fail thresholds are in the scenario functions in `harness.py` (they
are the harness author's reading of the spec, e.g. "marked down within 10 s",
"back up within 45 s") and are printed next to every check in the report.

## Docker/host networking caveat (important for N >= ~20)

Docker gives a (re)started container a new random MAC, and on a cold 40-container bridge the kernel
loses ARP exchanges and drops the first packets sent to a not yet resolved neighbour (visible as
UDP `SndbufErrors` in `/proc/net/snmp`; verified without unbound, with plain `bash /dev/udp`
bursts: ~1/3 of the packets lost).  The cluster module then sees 3 consecutive probe timeouts and
marks healthy peers down, which looks like a module bug but is not.  Therefore the harness

- restarts unbound *inside* the running containers for scenario resets (containers, network
  namespaces and MACs stay), and
- installs permanent ARP entries between all containers (`--static-arp`, default auto: N > 10),
  re-installed after the `docker stop`/`start` of scenario c.  With static entries `docker stop`
  behaves as a silent drop (no ARP failure / ICMP host unreachable); scenario c2 is the
  port-unreachable case.

Also: the host's `http_proxy` is ignored for the authority's HTTP stats port.

## Output

`<out>/report.md`, `<out>/results.json`, `<out>/raw/<scenario>/` (loadgen CSV
per run, per-node `stats_noreset` and `cluster_status`, node logs with
timestamps, authority summaries), `<out>/conf/`, `<out>/docker-compose.yml`.

## Limitations

- One host, one kernel: latencies are ~0.1 ms LAN RTTs; CPU contention with
  other host workloads makes the throughput numbers noisy.
- The load generator is Python (about 3-5k qps); the throughput test uses
  dnsperf.  Cache-hit throughput is measured for plain client queries; peer
  (CLUSTER option) queries cannot be generated by dnsperf.
- The authority is a single-threaded python server (a few thousand qps).
- Unbound's own UDP retransmits to a slow authority make the raw authority
  counts exceed 1 per name in g; the "distinct source nodes per name" metric
  is the robust one and both are reported.
- DNSSEC is not exercised (unsigned zone, `domain-insecure`).
- Loss/delay is only applied on egress of the victim (no ifb ingress shaping).
