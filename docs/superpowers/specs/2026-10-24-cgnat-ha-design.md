# vpp-cgnat: active/active CGNAT pair as a VPP plugin

## Intent

Two servers running VPP with this plugin form one complete CGNAT: active/active, with
every session synced, so a node can die and no customer notices. That includes open
connections, the customer's public IP and their ports. Traffic can arrive at either node
in either direction (ECMP from the core, asymmetric paths), and it just works. This is
the FortiGate CGNAT HA standard, on commodity VMs.

It's an open-source project (Apache-2.0, like VPP) that knows nothing about Underlay.
Underlay is one operator of it. Every Underlay site gets a pair of these as two VMs.

It replaces today's single det44 VM (cgnat-1). det44 has no HA. nat44-ei's HA is a stub:
its resync is a no-op, retransmits are truncated, and active/active deletes live
sessions. Neither has per-subscriber port blocks except det44's static ones.

## Goals

- **Active/active pair.** Both nodes translate. The operator's router may load-share in
  both directions (ECMP on the public pool and on the inside default) with any hashing.
- **Session survival.** When either node fails, established sessions continue on the
  survivor with the same public IP and port. This is the success test.
- **Deterministic port blocks** (RFC 7422 style). Each subscriber has a fixed public IP
  and port block computed from configuration. The mapping formula is the lawful record of
  who had public IP:port X, at any time, with no per-session logs needed. The formula is
  det44's, so existing records and Underlay's ledger stay valid:
  - `ratio = inside_size / outside_size`
  - `ports_per_sub = (65536 - 1024) / ratio`
  - `outside = outside_base + offset / ratio`
  - `port_lo = 1024 + ports_per_sub * (offset % ratio)`
  - offsets are counted from the inside prefix's base
  - several maps per node
- **Self-contained clustering.** Peer liveness, ownership, steering, session sync,
  failover and failback all live in the plugin. No sidecar daemon, no external
  coordinator.
- **Configured through VPP.** `startup.conf` section, CLI, and the binary API (for
  programs). Both nodes carry identical config except their own identity and peer.
- **Observable through VPP.** Stats segment counters and state, CLI `show`, and binary-API
  calls for: status, ownership, sync health, sessions, and forward/reverse lookup
  (subscriber → IP and block; IP:port → subscriber).
- **A "ready" state** that an operator's routing can watch, e.g. to withdraw a BGP
  announcement while a node resyncs. Exposed via stats and API; the plugin itself does no
  routing.

## Non-goals

- Routing protocols. BGP, statics and BFD on the router are the operator's choice. (We run
  BGP from both nodes with VPP's linux-cp and FRR on our network, but none of that is part
  of the plugin.)
- IPv6 or NAT64. IPv6 stays native and never touches the pair.
- ALGs (FTP, SIP, PPTP), for now.
- Clusters bigger than two nodes in the first version. Don't paint it into a corner: the
  ownership function should generalise.
- Per-session logging as the record. Optional IPFIX port-block events (natEvent 16/17)
  are fine.

## Anti-goals

- Anything that needs Underlay (or any external service) up to keep translating.
- A failover that changes anyone's public IP or ports.
- A design that only works if the router hashes traffic a particular way.

## How it works (decided)

- **Ownership.** Each subscriber has one owner node, a deterministic function of their
  inside address over the set of live nodes. In a healthy pair the owners split roughly
  evenly. When one node is down, the survivor owns everyone. Either node can find the
  subscriber for any packet:
  - outbound: from the inside source address
  - inbound: from the public IP and port, by the reverse formula
- **Steering.** A packet that arrives at a node that isn't the subscriber's owner is
  forwarded to the owner over a dedicated pair link, with enough information to process it
  as if it had arrived there. So correctness never depends on sync speed or router
  hashing.
- **Sessions** live on the owner.
  - Port choice is within the subscriber's block, det44-like: first try `port_lo +
    (inside_port % ports_per_sub)`, and probe on collision.
  - Timers are protocol- and state-aware, and configurable: TCP established, TCP
    transitory, UDP and ICMP.
  - The per-subscriber session cap is configurable (det44 hard-codes 1000).
- **Session sync.**
  - The owner streams session create, refresh and delete to its peer over UDP on the pair
    link. It's reliable: sequenced and acknowledged, retransmitted without truncation,
    and batched.
  - On peer join or return there's a full bulk resync.
  - The peer keeps a warm copy whose timers are kept alive by refreshes.
- **Failover.** Peer liveness is fast (sub-second), using BFD or the plugin's own
  heartbeat on the pair link. When the peer is lost, the survivor takes ownership of every
  subscriber and serves existing sessions from its warm copy.
- **Failback.** A returning node resyncs fully, then takes back its subscribers, with no
  session loss in either direction. It reports "ready" only once resynced.
- **NAT behaviour.**
  - Mapping is endpoint-independent (RFC 4787): same inside IP:port gives the same public
    IP:port whatever the destination.
  - Filtering is address-dependent by default, and configurable to endpoint-independent.
  - Hairpinning is supported.
- **Multi-worker correct.** It must be correct with several VPP worker threads, including
  packet handoff between workers. nat44-ei's port allocators got this wrong.

## Rulings (after the builder check)

- **Split-brain.** Liveness is checked on several paths: the pair link, plus the inside
  and outside networks. The two VMs share one switch fabric, so the pair link isn't
  independent.
  - A node takes over a peer's subscribers only if that peer is unreachable on all paths.
  - If only the pair link is down and the peer is visibly alive elsewhere, the
    higher-ID node fences itself: it drops "ready" and stops translating. It never
    double-allocates.
  - When the link returns: full resync, then both ready.
  - (Nick: "same fabric, just a second server". These are my calls; a redundant pair
    link can be added later.)
- **Config agreement.** Each node puts a hash of its maps and cluster config into every
  heartbeat and sync message.
  - On a mismatch, ownership freezes at the last agreed active set, and both say why.
    (Changed after the Phase 2 review: originally both nodes dropped "ready", which
    with routing glue took the whole pair out of service on any rolling config change.
    Now the serving node stays ready and raises the alarm; a node that isn't serving
    can't join until the configs agree.)
  - Removing a map flushes its sessions. Changing a map that has live sessions is
    refused (remove and re-add instead).
- **Subscriber identity** is (inside VRF, inside address) from day one, so maps in
  different inside VRFs may overlap. This applies to session keys, ownership, steering
  metadata, the API and lookups.
- **Cut-over from cgnat-1** keeps the mappings, not live sessions. The only CGNAT
  subscriber is the test line.
- **Design target** (an order of magnitude for sizing tables and sync; measured numbers
  come from testing): about 10k subscribers, 1M concurrent sessions, 50k new sessions per
  second and 10 Gbps per pair. With any-hash ECMP, about half of all traffic crosses the
  pair link, so plan link capacity for that.

## Constraints

- VPP 26.06, in C.
- One VPP table by default: inside and outside both in table 0. These are the
  box's own FIB tables, not the router's VRFs. Separate inside and outside
  tables are optional. (Nick, 2026-10-24: "single table default and keep it
  optional".) Outside traffic to an inside prefix is always dropped.
- Coexists with VPP's own plugins.
- Builds in-tree in a VPP checkout to start; out-of-tree packaging comes later.

## Underlay's integration (separate from the project)

- cgnatd keeps its job, but talks to the plugin through VPP's binary API (govpp) instead
  of vppctl. It:
  - pushes maps and the peer from Underlay
  - reads ownership, sync health and readiness into admin
  - answers port lookups
  - alerts on drift or silence
- The cut-over from cgnat-1 (det44) keeps everyone's mapping, because the formula is the
  same.

## Proof

1. **Unit and integration tests** in VPP's `make test` framework: translation,
   ownership, steering, sync, failover and failback.
2. **Two-VM lab on prox-hv01** (cgnat-a and cgnat-b):
   - both announce the pool to core0 by BGP
   - core0 runs multipath in PUBLIC and the CGNAT VRF
   - test line SVC-0004 stays on CGNAT, and the blaster provides load
3. **Pass criteria:**
   - Kill either node mid-download (long TCP flows, UDP streams): zero established-session
     loss, same public IP and port.
   - Forced asymmetric paths work.
   - Clean failback.
   - No mapping changes.
4. **Sizing is measured, not guessed:** sessions, new sessions per second, throughput,
   and sync bandwidth per pair at increasing load until it degrades.

## Left to the builder

- the pair-link encapsulation
- data structures
- the sync wire format
- BFD versus own heartbeat
- the exact ownership function
- the timer defaults (start from det44 and nat44 values)
- the stats layout
