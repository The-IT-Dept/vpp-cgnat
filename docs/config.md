# vpp-cgnat configuration reference

The plugin is configured three ways, which all do the same things:

- the `cgnat { }` section of `startup.conf` (global policy only)
- the VPP CLI
- the binary API, for programs (`cgnat.api`)

A node runs alone or as one of an active/active pair (see "The pair" below).

## startup.conf

```
cgnat {
  sessions-per-subscriber 1000          # sessions the subscriber opens
  inbound-sessions-per-subscriber 250   # opened towards it by inbound packets
  max-sessions-per-thread 1048576       # hard ceiling per worker
  timeouts { tcp-established 7440 tcp-transitory 240 udp 300 icmp 60 }
  filtering address-dependent           # or endpoint-independent
}
```

All values shown are the defaults. Timeouts are in seconds and must be greater
than 0.

Inbound-created sessions have their own budget, so outsiders who know a
subscriber's public IP:port can't use up the subscriber's sessions.

Memory: allow roughly 250 bytes per session, covering the mapping, the hash
entries and the filter refcount. Size the main heap for
`max-sessions-per-thread × workers × 250 B` plus headroom. For example, 4
workers at the default ceiling need about 1 GB: `memory { main-heap-size 2G }`.

## Maps

A map sends one inside prefix to one outside pool, using det44's formula:

```
ratio          = inside_size / outside_size        (power of two, >= 1)
ports_per_sub  = (65536 - 1024) / ratio
outside        = outside_base + offset / ratio
port_lo        = 1024 + ports_per_sub * (offset % ratio)
port_hi        = port_lo + ports_per_sub - 1
offset         = inside - inside_base
```

**Tables.** By default everything lives in VPP's main table (table id 0):
inside interface, outside interface, the route to the inside prefixes and the
default route. These are VPP's own FIB tables on the CGNAT box, nothing to do
with VRFs on the operator's router.

Putting the inside interface in a separate table is optional (`inside-vrf`,
`outside-vrf`, default 0). It's only useful when overlapping inside ranges
from different customers arrive on different inside interfaces.

A subscriber is identified by (inside table, inside address). Maps in
different inside tables may overlap. Maps in the same inside table may not,
and neither may outside pools in the same outside table.

There is no in-place edit. Deleting a map flushes its sessions, and you change
a map by deleting it and adding it again. Because the formula is fixed, a
re-added map gives every subscriber the same address and port block as before.

| | |
|---|---|
| CLI | `cgnat map add\|del inside <pfx> [inside-vrf <n>] outside <pfx> [outside-vrf <n>]` |
| CLI | `show cgnat maps` |
| API | `cgnat_map_add_del`, `cgnat_map_dump` / `cgnat_map_details` |

Example, using the det44 values that Underlay's ledger already uses:

```
vpp# cgnat map add inside 100.64.0.0/23 inside-vrf 1 outside 157.20.113.160/28
vpp# show cgnat lookup forward 100.64.0.5 inside-vrf 1
100.64.0.5 vrf 1 -> 157.20.113.160 ports 11104-13119
vpp# show cgnat lookup reverse 157.20.113.160:11104
157.20.113.160:11104 vrf 0 -> 100.64.0.5 vrf 1
```

## Lookups (the lawful record)

| | |
|---|---|
| CLI | `show cgnat lookup forward <addr> [inside-vrf <n>]` |
| CLI | `show cgnat lookup reverse <addr>:<port> [outside-vrf <n>]` |
| API | `cgnat_forward` (subscriber -> outside address, port_lo, port_hi) |
| API | `cgnat_reverse` (outside address:port -> inside VRF, subscriber) |

## Interfaces

Inside interfaces face subscribers and outside interfaces face the Internet.
Enabling an interface also enables shallow virtual reassembly on it, so every
fragment is translated with its flow's ports.

| | |
|---|---|
| CLI | `set interface cgnat in\|out <interface> [del]` |
| API | `cgnat_interface_add_del_feature` (`sw_if_index`, `is_inside`, `is_add`) |

Traffic that isn't the plugin's business passes through untouched: traffic
addressed to the box's own addresses on either side, and outside traffic not
addressed to a pool. One exception: outside traffic addressed to a mapped
inside prefix is dropped (`to-inside`), so even with a single table the
internet can never reach a subscriber directly. Traffic the plugin can't translate is dropped and counted,
and never forwarded untranslated. The drop counters, under
`/err/cgnat-in2out/…`, `/err/cgnat-out2in/…` and `/err/cgnat-hairpin/…`, are:

| counter | meaning |
|---|---|
| `no-map` | inside source is in no map |
| `no-mapping` | inbound to a pool address:port nobody holds, or an ICMP error for an unknown flow |
| `filtered` | inbound from a remote address the mapping never talked to (address-dependent filtering) |
| `cap` | subscriber at its session limit (outbound or inbound budget) |
| `table-full` | the worker's session table is at `max-sessions-per-thread` |
| `to-inside` | outside traffic addressed to an inside prefix |
| `options` | IPv4 options (VPP's ip4-input already punts these before the plugin) |
| `exhausted` | subscriber's port block is full |
| `unsupported` | protocol or ICMP type not translated (only TCP, UDP, ICMP echo and ICMP errors are) |
| `truncated` | L4 header missing |
| `congestion` | handoff queue to another worker was full |

## Policy

| | |
|---|---|
| CLI | `cgnat filtering address-dependent\|endpoint-independent` |
| CLI | `cgnat sessions-per-subscriber <n>` |
| CLI | `cgnat inbound-sessions-per-subscriber <n>` |
| CLI | `cgnat max-sessions-per-thread <n>` |
| CLI | `cgnat timeouts [tcp-established <s>] [tcp-transitory <s>] [udp <s>] [icmp <s>]` |
| API | `cgnat_set_filtering`, `cgnat_set_session_limit`, `cgnat_set_timeouts` |

Mapping is always endpoint-independent (RFC 4787): the same inside IP:port gets
the same outside port whatever the destination. A new mapping first tries
`port_lo + inside_port % ports_per_sub`, then probes upward through the block,
wrapping around. So after a mapping expires, the same inside port usually gets
the same outside port again.

TCP sessions use the transitory timeout until a SYN has been seen in both
directions. They return to it after a FIN in both directions or a RST.

## Observability

| | |
|---|---|
| CLI | `show cgnat status` |
| CLI | `show cgnat sessions [subscriber <addr> [inside-vrf <n>]]` |
| API | `cgnat_get_status` (maps, sessions, mappings, subscribers, policy) |
| API | `cgnat_session_dump` (`all`, or `in_vrf` + `in_addr`) / `cgnat_session_details` |
| Stats | `/cgnat/in2out-packets`, `/cgnat/out2in-packets`, `/cgnat/hairpin-packets` |
| Stats | `/cgnat/sessions`, `/cgnat/mappings`, `/cgnat/subscribers` (per-thread gauges; sum them) |

## Threads

Each subscriber belongs to one worker:
`first_worker + xxhash(inside fib, inside addr) % n_workers`.

- Outbound packets find the owner from the source address.
- Inbound packets find it from the pool address and port, using the reverse formula.

A packet that arrives on the wrong worker is handed to the owner, so no
session state is shared between workers.

Each worker expires its own sessions:

- **Pace:** a walk runs ten times a second, in 0.5 ms slices that re-arm
  until the backlog is clear.
- **Lookups:** a session that's past its timeout counts as gone even if the
  walk hasn't reached it yet.

**Cost of a session dump:** `show cgnat sessions` and `cgnat_session_dump`
run with the workers paused and walk every session. Avoid them on a busy box.
For a single subscriber, `cgnat_forward` and `cgnat_reverse` cost nothing.

## The pair

Two nodes with identical maps and policy form one CGNAT:

- **Ownership:** every subscriber has one owner node, chosen by rendezvous hashing over the nodes that are live and ready.
- **Steering:** either node may receive any packet in either direction. Packets for the peer's subscribers are steered to it over the pair link.
- **Sync:** the owner streams every session to the peer, which keeps a warm copy.
- **Failover:** when a node dies, the survivor already holds every session, with the same public IP and ports.

### Configuration (startup.conf)

```
cgnat {
  cluster {
    node-id 1                              # 1..255, different on each node
    local 10.255.124.1 peer 10.255.124.2   # the pair link (steering, sync, HELLO)
    path local 157.20.113.243 peer 157.20.113.245   # extra liveness paths (up to 4)
    path local 10.1.2.5 peer 10.1.2.7
    # hello-interval 100   dead-interval 500   refresh-interval 10   port 6200
  }
}
```

**Configure the cluster in `startup.conf`, not in the startup CLI script.** That
way it is on (starting) before any interface or map exists, so the node never
translates on its own before it has joined its peer.

The same settings are available via the CLI (`cgnat cluster …`, `cgnat cluster path add|del …`) and the API (`cgnat_cluster_set`, `cgnat_cluster_path_add_del`). `show cgnat cluster` and `cgnat_cluster_get_status` show the node and its peer. `cgnat_cluster_owner` tells you which node owns a subscriber.

### Paths and split brain

- **The pair link** carries HELLOs, steered packets and sync. Make it a dedicated, directly connected link: a VLAN between the two nodes.
- **Extra paths** carry HELLOs only. Put them on other networks, such as each node's inside and outside links through the router, so that losing the pair link can be told apart from losing the peer.
- A path is **alive** only in both directions: we hear the peer, and it says it hears us.
- A node takes over the peer's subscribers only when the peer is silent on every path.
- If the pair link is down but the peer is alive on another path, the node with the **higher id fences**: it stops translating and reports not ready. When the link returns it resyncs, then serves again.

### Ready, and what routing should watch

`/cgnat/cluster/ready` (stats gauge) and `ready` in the status API mean the node
should receive traffic. Route to a node only while it is ready. Example glue:
static routes on the router with BFD-checked next hops, and
`contrib/cgnat-ready-bfd.sh` on each node keeping its BFD sessions admin-up only
while ready.

| reason | ready | meaning |
|---|---|---|
| `starting` | no | First dead interval after the pair-link address exists. Can't hear the peer yet. |
| `unconfigured` | no | No maps: nothing to translate. |
| `alone` | yes | Peer silent on every path. This node owns everyone. |
| `none` | yes | Pair up, owners split. |
| `resyncing` | no | Joining a ready peer. Pulls its whole table, then waits for the peer to include it (two-phase) before taking subscribers. |
| `fenced` | no | Pair link down, peer alive elsewhere, higher id. |
| `config-mismatch` | as before | Maps or policy differ from the peer. The serving node stays ready and raises this alarm. Ownership is frozen and a node that isn't serving can't join until the configs agree. |
| `duplicate-node-id` | no | The peer uses our node id. |

A node that is already serving stays the incumbent: a joining or restarting peer
resyncs from it. If the same peer incarnation comes back after a gap, the higher
id resyncs from the lower.

### Pair-link MTU

Steered packets are encapsulated with 56 bytes of headers. Give the pair link an
MTU of at least 1600 (jumbo is better) so full-size packets aren't fragmented.
Fragmented steered packets do work, but each one costs a full reassembly at
the owner. SYNC packets are up to 1360 bytes.

### Security

The pair protocol is UDP 6200. A node accepts:

- HELLOs only from a configured path's peer, to that path's local address, with TTL 255 on the pair link (254 on extra paths, which may cross one router).
- Everything else (steer, sync, ack, resync) only from the pair-link peer with TTL 255.
- Sync records only if their public IP:port lies in the subscriber's block by the formula.

**On the router, drop UDP 6200 towards the nodes' inside and outside addresses
from anywhere except the nodes themselves.**

### Wire protocol (v1)

Network byte order. Every message starts with a 16-byte header:
`version, type, flags, node_id, config_hash, epoch, seq`.

| type | body |
|---|---|
| 1 HELLO | path_id, state (ready, fenced, want_resync, peer_in_active), n_workers, first_worker, heard_epoch |
| 2 STEER | direction (in2out, out2in, hairpin), reassembly flags, tcp flags or icmp type, table_id, l4 ports; then the original IPv4 packet |
| 3 SYNC | src_thread, dst_thread, n_records, oldest_unacked; then 32-byte records (op, proto, tcp state, timeout class, inside table, inside ip:port, outside ip:port, remote ip:port, idle) |
| 4 ACK | src_thread, dst_thread; header seq = highest in-order seq received |
| 5 RESYNC_REQ | none |
| 6 RESYNC_END | src_thread, n_src_threads |

`cgnat_proto.h` is the reference.

### Sync behaviour

- **What is sent:** records go out on session create, on a timeout-class change, at most every `refresh-interval` while a session is active, and on delete.
- **Streams:** one per (local worker, peer worker), batched up to 40 records. They are sequenced and applied strictly in order, with a cumulative ACK and go-back-N retransmit after 50 ms.
- **Falling behind:** a stream more than `window` packets behind (default 1024), or a thread holding 4096 unacked packets, gives up the oldest and asks the peer to pull a full resync.
- **Warm copies:** these expire `refresh-interval` after the session's own timeout.
- **Who wins:** an owner never takes state from its peer for a live session it owns. A copy of a session whose subscriber has moved to the peer takes the peer's records.
