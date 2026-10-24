# vpp-cgnat configuration reference

The plugin is configured three ways, which all do the same things:

- the `cgnat { }` section of `startup.conf` (global policy only)
- the VPP CLI
- the binary API, for programs (`cgnat.api`)

Phase 1 is a single node. Pair and cluster settings arrive with Phase 2.

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
