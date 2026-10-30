# vpp-cgnat

A carrier-grade NAT plugin for [VPP](https://fd.io), built around
**deterministic port blocks**. The goal is an **active/active HA pair** on
commodity servers.

> **Status:** the single node (Phase 1) and the active/active pair (Phase 2) are
> done, tested in VPP's `make test` (184 tests) and in a two-VPP lab with real
> TCP/UDP flows and kill/restore, and running in production in front of an ISP
> core router on SR-IOV VFs: about 2.0 Mpps lossless and 2.9 Mpps peak on two
> worker cores. See
> [the design](docs/superpowers/specs/2026-10-24-cgnat-ha-design.md),
> [configuration](docs/config.md) and [SR-IOV](docs/sriov.md).

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
- **Interface and next-hop monitoring:** a node is not ready while any translating interface is down or has no link. It takes subscribers from its peer only once VPP can forward via every neighbour on those interfaces, so a BFD session that isn't up yet, or a lost router, keeps them on the peer.

**Two-VPP lab** ([lab/ha](lab/ha/README.md)): a router namespace load-shares
both directions across both nodes. 12 TCP streams and 16 UDP flows run while
node B is killed with `kill -9` at 15 s and restarted at 35 s:

| | result |
|---|---|
| without the pair (two independent nodes) | FAIL: UDP flows lose everything, TCP connections fail |
| with the pair | PASS (repeatable): 14/14 TCP connections kept with the same public IP:port, no throughput dip at kill or restore, UDP worst gap per flow 0.6 s (failure detection + route change) |

**Production proof.** Two VMs (2 workers each) in front of a Juniper MX204:
static routes with BFD-checked next hops, ECMP, and
`contrib/cgnat-ready-bfd.sh` on each node. The tests ran on a real subscriber
line (IPoE via the MX's BNG, CGNAT VRF):

- **On virtio (2026-10-24):** a 792 MB HTTP download completed byte-perfect over one TCP connection while node 1 was killed with `kill -9` mid-transfer, restarted and rejoined, and then node 2 was killed. The connection kept the same public IP:port throughout. A 1-second ping through the same line lost 4 of 150 packets across the four events.
- **On SR-IOV VFs (2026-10-25):** the owner was killed, rejoined, and then the other node was killed. An 800 MB download from our server and the Debian ISO from a public mirror each completed with SHA-256 intact, over one TCP connection with the same public IP:port. A 0.2 s ping lost 0.6 s at the owner's kill, nothing at the rejoin, and 0.2 s at the second kill. Getting there on VFs took fixes for three start-up timing gaps that virtio hid: see [docs/sriov.md](docs/sriov.md#failover-lessons-from-vfs).

**Dual sessions, shown on the live pair:** two subscribers whose owners are
different nodes, each node's table dumped over the API:

| subscriber | owner | node 1 | node 2 |
|---|---|---|---|
| 100.64.0.1 | node 1 | 2 sessions, owned | the same 2, warm |
| 100.64.0.6 | node 2 | the same 5, warm | 5 sessions, owned |

Both nodes held the identical 7 sessions with the same public IP:port. Re-run on the final SR-IOV build: both nodes held the identical 4 sessions (2 for 100.64.0.1 owned on node 1, 2 for 100.64.0.6 owned on node 2), each owned on exactly one node and warm on the other.

**Throughput in the VMs, measured on the production nodes.** A DPDK generator
VM sent 64-byte UDP from 4096 subscribers × 63 flows through a test map, to a
node with 2 workers on pinned host cores:

| node, I/O | lossless up to | best forwarded | limited by |
|---|---|---|---|
| cgnat-1, **SR-IOV VFs** (DPDK) | **~2.0 Mpps** | **~2.9 Mpps** (at 4 Mpps offered) | CGNAT worker CPU |
| cgnat-2, DPDK on virtio | 280 kpps | 426 kpps | host vhost-net/OVS |
| cgnat-1, DPDK on virtio | 255 kpps | 477 kpps | host vhost-net/OVS |
| cgnat-1, `af_packet` (kernel virtio-net) | 130 kpps | 172 kpps | guest kernel (collapses to 99 kpps at 1 Mpps) |

- **SR-IOV is about 7× virtio and 15× the kernel path** on the same two cores. On virtio the CGNAT had headroom (1,100–1,500 clocks per packet, vectors far from full) and the host's software switching was the ceiling. On VFs the workers are the limit: full vectors at about 670–1,000 clocks per packet, no NIC receive drops, and overload shed at the worker handoff without collapsing.
- **2.0 Mpps lossless is about 14 Gb/s** at a typical ~900-byte average packet, more than the 10G port carries.
- **Running on VFs** needs a small VPP patch (VLAN strip for host-enforced VLANs) and has failover timing lessons: see [docs/sriov.md](docs/sriov.md).

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

For dedicated cores and real NICs, see the SR-IOV numbers above. Raw results
are in `bench/`.

## Building and testing

The plugin builds in-tree in a VPP 26.06 checkout, with three VPP patches.
Out-of-tree packaging comes later.

```
git clone https://github.com/FDio/vpp ~/vpp && cd ~/vpp && git checkout v26.06
~/vpp-cgnat/scripts/apply-patches.sh ~/vpp  # patches/series, in order
make install-dep
~/vpp-cgnat/scripts/link-into-vpp.sh        # symlinks src/plugins/cgnat into ~/vpp
~/vpp-cgnat/scripts/check-patches.sh ~/vpp  # v26.06 + patches/series exactly?
cd ~/vpp && make build                      # or make build-release, make pkg-deb
~/vpp-cgnat/scripts/test.sh test_cgnat      # VPP make test with this repo's tests
```

The patches, in `patches/series` order:

| patch | why |
|---|---|
| `vpp-26.06-dpdk-vlan-strip.patch` | a `vlan-strip-offload on` device option. SR-IOV VFs with a host-enforced VLAN hand frames up still tagged, and VPP drops them ([sriov.md](docs/sriov.md#what-vpp-needs)) |
| `vpp-26.06-time-monotonic.patch` | backport of master 7d65ef4b8. 26.06's per-thread clocks drift apart with uptime, which wedged BFD on both nodes ([clock-skew.md](docs/clock-skew.md)). Drop it on a base that has it |
| `vpp-26.06-bfd-advertise-effective-tx.patch` | BFD advertises the DesiredMinTx it transmits at (Junos flapped the sessions otherwise), times on one clock on every thread, and has `test time worker-skew` for the tests. Needs the time patch |

`apply-patches.sh` wants a clean v26.06, applies with `git apply --index` (no
fuzz) and leaves the tree untouched if any patch fails. `check-patches.sh`
fails unless the tracked files are exactly v26.06 + `patches/series`, and
prints the tree hash. Run it before building anything that ships;
`scripts/remote.sh` runs it before every build.

The test suites run in VPP's own framework: `test/test_cgnat.py` (84 tests,
the single node with 0, 1 and 2 workers) and `test/test_cgnat_cluster.py`
(100 tests, the pair against a scapy-emulated peer). Both include tests with
the worker's clock 5 s ahead of or behind main's. VPP's own `TEST=bfd` and
`TEST=test_time` cover the BFD and time patches. `scripts/remote.sh` syncs to
a build VM, rebuilds and runs a test from a workstation.

## Roadmap

1. **Phase 1 — single node:** done.
2. **Phase 2 — the pair:** done. Multi-path liveness with split-brain fencing, ownership and steering, reliable sync with full resync, failover and failback without losing established sessions, readiness for routing, and interface and next-hop monitoring.
3. **Production proof:** done on virtio and on SR-IOV VFs, with static routes and BFD on a Juniper MX204 (see above). BGP announcement of the pool, as an alternative to static routes, is not built.
4. **Next:** out-of-tree packaging, and a management agent driving maps over the binary API.

## Licence

Apache-2.0, like VPP.
