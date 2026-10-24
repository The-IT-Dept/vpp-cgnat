# vpp-cgnat

A carrier-grade NAT plugin for [VPP](https://fd.io), built around
**deterministic port blocks**. The goal is an **active/active HA pair** on
commodity servers.

> **Status:** the single node (Phase 1) and the active/active pair (Phase 2) are
> done and tested in VPP's `make test` (165 tests) and in a two-VPP lab with real
> TCP/UDP flows and kill/restore. Production proof on two VMs is next. See
> [the design](docs/superpowers/specs/2026-10-24-cgnat-ha-design.md) and
> [configuration](docs/config.md).

## Why

VPP ships two NAT44 flavours. Neither does what a small ISP needs from CGNAT:

- **det44** has deterministic port blocks but no HA.
- **nat44-ei** has HA, but it's a stub: resync is a no-op, retransmits are
  truncated, and active/active deletes peer sessions. It also has no
  per-subscriber port blocks.

vpp-cgnat aims for the FortiGate-style standard: two boxes, both forwarding,
every session synced, and a node can die without any customer noticing.

## What it does (Phase 1)

- **Deterministic port blocks** using det44's formula. A subscriber's public
  IP and port range are computed from configuration, so the formula itself
  is the lawful record of "who had IP:port X". No per-session logs are
  needed, and records made under det44 stay valid.
  ```
  ratio         = inside_size / outside_size
  ports_per_sub = (65536 - 1024) / ratio
  outside       = outside_base + offset / ratio
  port_lo       = 1024 + ports_per_sub * (offset % ratio)
  ```
- **Mapping** is endpoint-independent (RFC 4787): the same inside IP:port
  gets the same public port whatever the destination.
- **Filtering** is address-dependent by default and can be set to
  endpoint-independent. **Hairpinning** is supported.
- **Protocols:** TCP, UDP, ICMP echo, and ICMP errors with the quoted packet
  translated in both directions. Fragments are handled with VPP's shallow
  virtual reassembly.
- **Timers** are state-aware and configurable: TCP established, TCP
  transitory, UDP and ICMP. Expiry runs per worker and is time-sliced.
- **Limits:**
  - per subscriber, for sessions the subscriber opens (default 1000)
  - a separate per-subscriber budget for sessions opened by inbound packets
    (default 250), so outsiders can't use up a subscriber's sessions
  - a hard ceiling per worker
- **Multi-worker.** Each subscriber is owned by one worker. Outbound packets
  find it from the source address; inbound packets find it from the public
  IP:port via the reverse formula. Packets on the wrong worker are handed
  off, so no state is shared between workers.
- **Never leaks.** Traffic that can't be translated is dropped and counted,
  never forwarded untranslated. Outside traffic addressed to an inside
  prefix is dropped.
- **Configured through VPP:** `startup.conf`, CLI and the binary API.
  **Observable through VPP:** stats-segment counters and gauges,
  `show cgnat …`, and API dumps. Forward and reverse lookups are available
  over the API for "who had this IP:port".

Reference: [docs/config.md](docs/config.md).

```
cgnat map add inside 100.64.0.0/23 outside 157.20.113.160/28
set interface cgnat in  <inside-interface>
set interface cgnat out <outside-interface>

vpp# show cgnat lookup forward 100.64.0.5
100.64.0.5 vrf 0 -> 157.20.113.160 ports 11104-13119
vpp# show cgnat lookup reverse 157.20.113.160:11104
157.20.113.160:11104 vrf 0 -> 100.64.0.5 vrf 0
```

## The pair

Two nodes, both translating.

- **Who serves whom:** each subscriber has one owner node (rendezvous hashing over the live, ready nodes). A packet that lands on the other node is steered to the owner over a dedicated pair link, so the router can hash both directions however it likes.
- **Sync:** owners stream every session to the peer, batched, sequenced, acknowledged and retransmitted, with full resync. The peer holds warm copies.
- **Failover:** when a node dies, the survivor already holds everything. Established sessions continue with the same public IP and port.
- **Failback:** a returning node pulls the whole table, then takes its subscribers back in two phases.
- **Split brain:** liveness runs on several paths. If only the pair link fails, the higher id fences.
- **Readiness:** the plugin exposes "ready" for the operator's routing to watch. `contrib/cgnat-ready-bfd.sh` keeps BFD up only while ready. The plugin itself does no routing.

**Two-VPP lab** ([lab/ha](lab/ha/README.md)): a router namespace load-shares
both directions across both nodes. 12 TCP streams and 16 UDP flows run while
node B is killed with `kill -9` at 15 s and restarted at 35 s:

| | result |
|---|---|
| without the pair (two independent nodes) | FAIL: UDP flows lose everything, TCP connections fail |
| with the pair | PASS (repeatable): 14/14 TCP connections kept with the same public IP:port, no throughput dip at kill or restore, UDP worst gap per flow 0.6 s (failure detection + route change) |

## Performance (single node, packet generator)

Release build on an 8-vCPU VM on a busy shared host, VPP's packet generator,
64-byte UDP. These numbers are a floor, not a ceiling. The generator shares
each worker's core, and at about 1.5 Mpps per worker it is the bottleneck.

| | 1 worker |
|---|---|
| new sessions | 160–380k sessions/s (varies run to run on this host) |
| established flows, 15k flows | 1.54 Mpps (generator-bound); cgnat node 723 clocks/pkt |
| established flows, 1M flows | 1.45 Mpps; cgnat node 1350 clocks/pkt |
| memory | about 215 bytes per session |

Proper numbers on dedicated cores with DPDK NICs and a real traffic generator
are still to do. Raw results are in `bench/`.

## Building and testing

The plugin builds in-tree in a VPP 26.06 checkout. Out-of-tree packaging
comes later.

```
git clone https://github.com/FDio/vpp ~/vpp && cd ~/vpp && git checkout v26.06
make install-dep && make build
~/vpp-cgnat/scripts/link-into-vpp.sh        # symlinks src/plugins/cgnat into ~/vpp
cd ~/vpp && make build                      # or make build-release
~/vpp-cgnat/scripts/test.sh test_cgnat      # VPP make test with this repo's tests
```

The test suite is `test/test_cgnat.py`: 79 tests in VPP's own framework,
covering every class above with 0 and 2 workers. `scripts/remote.sh` syncs to
a build VM, rebuilds and runs a test from a workstation.

## Roadmap

1. **Phase 1 — single node** (this release).
2. **Phase 2 — the pair:**
   - liveness on several paths, with split-brain fencing
   - subscriber ownership across nodes and steering over a pair link
   - reliable batched session sync with full resync
   - failover and failback with zero established-session loss
   - a "ready" state the operator's routing can watch
3. **Lab proof:** two VMs announcing the pool by BGP with ECMP from the core,
   real subscriber traffic, killing a node mid-download, and sizing measured
   to the point of degradation.

## Licence

Apache-2.0, like VPP.
