# Two-VPP HA lab (single host, network namespaces)

Proves the pair end to end on one Linux box: two VPPs (A = node 1, B = node 2),
a router namespace that load-shares both directions across them (as the
operator's core does with ECMP), and real TCP/UDP flows through it while a node
is killed and restored.

```
 cli (100.64.0.10-.29) ── rtr ──┬─ br-in  10.1.0.0/24 ── A tap0 .2 / B tap0 .3   (inside)
                                └─ br-out 10.2.0.0/24 ── A tap1 .2 / B tap1 .3   (outside)
 srv (198.51.100.10)  ── rtr          A memif 10.255.0.1 ═══ B memif 10.255.0.2   (pair link)
```

- **`rtr` routing:**
  - subscriber traffic is policy-routed (`iif rtr-cli → table 100`) to a default via both nodes' inside addresses
  - the pool `192.0.2.0/28` is routed via both nodes' outside addresses
  - `fib_multipath_hash_policy=1` hashes on L4, so most flows take a different node in each direction
- **`watch.sh`** stands in for the operator's routing (BGP or BFD): a node's next hops are present only while it reports `ready`.
- **The cluster is configured in `startup.conf`**, so it is on (starting) before any interface exists. A node never translates alone and never claims to be alone before its pair-link address is up.

Run (release build of VPP with the plugin in `~/vpp`):

```
lab/ha/up.sh               # or: up.sh nocluster  (both nodes independent, for comparison)
lab/ha/test-failover.sh 60 15 35   # 60 s of traffic, kill -9 B at 15 s, restart it at 35 s
lab/ha/down.sh
```

`test-failover.sh` runs two iperf3 clients (8 + 4 TCP streams) and 16 UDP flows
(10 pps each, one subscriber per flow). It checks:

- both iperf3 runs complete, and throughput is never zero for more than 2 s
- the same 14 TCP connections, with the same public IP:port, before and after
- every UDP flow keeps one public IP:port throughout
- UDP loss per flow is at most 2 s worth per event
- the mapping is unchanged
- both nodes steered traffic over the pair link (the paths really were asymmetric)
- both nodes are ready at the end

## Results (2026-10-24, vppdev 8 vCPU, release build, 1 worker per node)

| run | result | TCP | UDP worst gap per flow (kill + restore) |
|---|---|---|---|
| no cluster (baseline) | FAIL | 6 of 9 connections at start | 260 of 260 packets lost on some flows |
| pair, run 1 | PASS | 14/14 connections kept, no throughput dip at either event | 0.72 s |
| pair, run 2 | PASS | 14/14 connections kept, no throughput dip at either event | 0.72 s |

The UDP gap is the failure detection time (500 ms dead interval) plus the
route update. Raw logs: `results-2026-10-24-*.txt`.
