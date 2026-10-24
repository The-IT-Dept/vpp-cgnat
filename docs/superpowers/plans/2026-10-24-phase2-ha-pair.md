# vpp-cgnat Phase 2: the active/active HA pair

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two VPP nodes running the cgnat plugin form one CGNAT. Either node may receive any packet in either direction. Every session is synced, and killing either node loses no established session and changes no public IP or port.

**Architecture:**

- **Liveness:** each node sends HELLOs on a pair link and on optional extra paths, over UDP.
- **Ownership:** each subscriber has one owner node, chosen by rendezvous hashing over the nodes that are live and ready. A node that receives a packet for a subscriber it doesn't own steers it to the owner over the pair link, encapsulated.
- **Sync:** the owner streams session records (upsert or delete) to the peer in sequenced, acknowledged, batched packets. These go per (sender thread → receiver thread) stream, so the receiver applies each packet on the subscriber's owning thread with no further handoff.
- **Warm copies:** the peer's copies live in the same tables, flagged `warm`. On failover the survivor already holds every session. On failback the returning node resyncs in full, and only then reports ready and takes its subscribers back.

**Tech Stack:** C (VPP 26.06 plugin), VPP `make test` with scapy acting as the peer. The integration harness is bash, Linux network namespaces, two VPP processes, and iperf3/socat.

**Spec:** `docs/superpowers/specs/2026-10-24-cgnat-ha-design.md` (Goals, How it works, Rulings, Proof). Phase 1 plan and ledger: `docs/superpowers/plans/2026-10-24-phase1-single-node-plugin.md`.

## Global Constraints

- VPP v26.06, C, in-tree. Same repo layout and scripts as Phase 1 (`scripts/remote.sh`, `scripts/test.sh`). Branch `phase2-ha-pair`, cut from `phase1-single-node`.
- No routing protocol in the plugin. "Ready" is exposed via stats and the API for the operator's routing to watch.
- Nothing may require an external service to keep translating.
- A failover must never change a subscriber's public IP or port. The det44 formula and the port first choice are unchanged.
- Two nodes in this version. The ownership function must generalise to N (rendezvous hashing does).
- **Split-brain.** A node takes over a peer's subscribers only when that peer is silent on every path. If only the pair link is down and the peer is alive elsewhere, the node with the higher ID fences: it drops ready and stops translating.
- **Config agreement.** A hash of maps, policy and cluster timers goes in every HELLO. On a mismatch, both nodes drop ready, report `config-mismatch`, and freeze ownership at the last agreed active set.
- Removing a map flushes its sessions on each node (configs are identical, so both flush).
- Subscriber identity is (inside table, inside address) everywhere: records, steering, ownership.
- One VPP table by default, with separate inside/outside tables optional. The pair link and probe paths may sit in any table (`table <id>`, default 0).

**Wire protocol** (UDP, default port **6200**, network byte order; every message starts with a 16-byte header):

```
header:  u8 version(=1) | u8 type | u8 flags | u8 node_id | u32 config_hash | u32 epoch | u32 seq
type 1 HELLO       body: u8 path_id | u8 state (bit0 ready, bit1 fenced, bit2 want_resync) | u16 n_workers | u16 first_worker | u16 pad
type 2 STEER       body: u8 direction (0 in2out, 1 out2in, 2 hairpin) | u8 pad | u16 pad | u32 table_id  ; then the original IPv4 packet
type 3 SYNC        body: u16 src_thread | u16 dst_thread | u16 n_records | u16 pad ; then n_records x 32-byte records ; header.seq = stream seq
type 4 ACK         body: u16 src_thread | u16 dst_thread | u32 pad ; header.seq = highest contiguous seq received on that stream
type 5 RESYNC_REQ  body: none
type 6 RESYNC_END  body: u16 src_thread | u16 n_src_threads
record (32 B): u8 op (1 upsert, 2 delete) | u8 proto (cgnat_proto_t) | u8 tcp_state | u8 to_class |
               u32 in_table_id | u32 in_addr | u32 out_addr | u16 in_port | u16 out_port |
               u32 remote_addr | u16 remote_port | u16 idle_ds (deciseconds idle, saturating) | u32 pad
```

- `epoch` is random per boot. A changed epoch from the same node_id means the peer restarted: reset all streams to it, and expect it to request a resync.
- **Timer defaults:**
  - hello-interval 100 ms
  - dead-interval 500 ms (a path is dead after this long with no HELLO)
  - refresh-interval 10 s (re-sync a touched session at most this often)
  - sync flush 10 ms
  - retransmit timeout 50 ms
  - stream window 1024 packets
  - warm sessions expire at `last_heard + timeout + refresh-interval`

**Configuration:**

```
cgnat { cluster {
  node-id <1..255>
  local <ip4> peer <ip4> [table <id>] [port 6200]          # the pair link
  path local <ip4> peer <ip4> [table <id>]                  # extra liveness paths (0..4)
  hello-interval <ms>  dead-interval <ms>  refresh-interval <s>
} }
```

The same settings are available as CLI (`cgnat cluster …`, `show cgnat cluster`) and API (`cgnat_cluster_set`, `cgnat_cluster_path_add_del`, `cgnat_cluster_get_status`, `cgnat_cluster_owner`). Without a `cluster` section, Phase 1 behaviour is unchanged: the node is alone and always ready.

## Review Focus

1. **The peer restarts within the dead interval** (new epoch, same node-id). Treat it as a new peer: reset streams, don't trust old sequence numbers, and keep ownership until it has resynced. (Test: Task 5, `test_peer_fast_restart_resets_streams`.)
2. **Sync loss beyond the window** (the pair link flaps for longer than the window). The stream overflows, a full resync is requested, nothing crashes and no session is lost on the sender. (Test: Task 4, `test_window_overflow_triggers_resync`.)
3. **A steered full-size packet exceeds the pair-link MTU.** The outer packet fragments (outer DF clear) and the receiver reassembles and translates it. (Test: Task 3, `test_steer_large_packet_fragments_and_reassembles`.)
4. **A sync record for a map this node doesn't have** (config drift mid-flight). The record is rejected and counted (`sync-unknown-map`), and no stray mapping is created. (Test: Task 4, `test_record_for_unknown_map_rejected`.)
5. **Both nodes configured with the same node-id.** The peer is never considered alive, the status says `duplicate-node-id`, and the node is not ready. (Test: Task 1, `test_duplicate_node_id_refused`.)

---

### Task 1: Cluster config, HELLOs, liveness, config hash

**Files:**
- Create: `src/plugins/cgnat/cgnat_cluster.h`, `cgnat_cluster.c` (config, state, HELLO process), `cgnat_cluster_input.c` (UDP 6200 receive node, HELLO handling), `cgnat_proto.h` (wire structs above, `CLIB_PACKED`)
- Modify: `cgnat.h` (cluster state in `cgnat_main_t`), `cgnat.c` (startup `cluster { }`), `cgnat_cli.c`, `cgnat.api`, `cgnat_api.c`, `CMakeLists.txt`
- Test: `test/test_cgnat_cluster.py` (new file, class `TestCgnatClusterHello`), `test/cgnat_peer.py` (scapy helpers: build and parse every message type)

**Interfaces:**
- Produces:
  - `typedef struct { ip4_address_t local, peer; u32 fib_index, table_id; f64 last_rx; u8 alive; } cgnat_path_t;`
  - Path 0 is the pair link.
  - `cgnat_cluster_t` (in `cgnat_main_t`) holds:
    - `u8 enabled, node_id, peer_node_id`
    - `u32 epoch, peer_epoch, config_hash, peer_config_hash`
    - `u16 port`
    - `cgnat_path_t *paths`
    - `f64 hello_interval, dead_interval, refresh_interval`
    - `u16 peer_n_workers, peer_first_worker`
    - `u8 peer_ready, peer_fenced, peer_want_resync`
    - `u8 ready, fenced`
    - `cgnat_cluster_reason_t reason`
  - `u32 cgnat_config_hash (void);` covers maps sorted by (in_table, in_prefix), timeouts, limits, filtering, hello/dead/refresh intervals.
  - `int cgnat_cluster_peer_alive (void);` (any path alive), and `int cgnat_cluster_pair_alive (void);`
  - `vlib_buffer_t *cgnat_cluster_alloc (vlib_main_t *vm, u32 path, u8 type, u32 seq, u32 body_len, void **body, u32 *bi);` builds outer IPv4/UDP and the header in a fresh buffer (outer DF clear, TTL 64), with `sw_if_index[VLIB_TX]` = the path fib.
  - `void cgnat_cluster_send (vlib_main_t *vm, u32 bi);` enqueues to ip4-lookup from any thread.
  - Reasons: `none`, `starting`, `alone`, `resyncing`, `config-mismatch`, `fenced`, `duplicate-node-id`.
  - API `cgnat_cluster_get_status` → node_id, peer_node_id, enabled, ready, fenced, reason (string 32), peer_alive, pair_alive, peer_ready, config_hash, peer_config_hash, epoch, peer_epoch.

- [ ] **Step 1: Write the failing tests.** Topology:
  - pg0 inside, pg1 outside, both in table 0
  - pg2 pair link, local 10.255.0.1 and peer = pg2.remote_ip4
  - pg3 probe path

  Configure through the API in setUp: `cgnat_cluster_set(node_id=1, local=pg2.local_ip4, peer=pg2.remote_ip4, hello_interval_ms=100, dead_interval_ms=500)`.

```python
def test_hello_sent(self):              # capture on pg2 within 0.5s: UDP 6200->6200, header v1 type 1 node 1, config_hash == status.config_hash, epoch != 0
def test_peer_alive_and_dead(self):     # inject peer HELLOs (node 2, ready) every 100ms for 1s -> status.peer_alive; stop; after 0.7s -> not peer_alive
def test_starting_then_alone(self):     # right after cgnat_cluster_set: reason "starting", not ready, subscriber traffic dropped (not-ready); after 0.7s: ready, reason "alone"
def test_config_hash_tracks_maps(self): # hash changes after cgnat map add, returns to old value after del
def test_config_mismatch(self):         # peer HELLO with another hash -> not ready, reason "config-mismatch"
def test_duplicate_node_id_refused(self): # peer HELLO with node_id 1 -> not peer_alive, reason "duplicate-node-id", not ready
def test_probe_path_hello(self):        # cgnat_cluster_path_add_del(local=pg3.local_ip4, peer=pg3.remote_ip4) -> HELLOs on pg3 with path_id 1
```

- [ ] **Step 2: Run them to make sure they fail.** `scripts/remote.sh test_cgnat_cluster`. Expected: AttributeError (no cluster API).
- [ ] **Step 3: Implement.**
  - A main-thread process sends HELLO on every path each hello-interval, evaluates liveness and ready each tick, and on change updates the stats gauges `/cgnat/cluster/ready`, `/cgnat/cluster/peer-alive` and `/cgnat/cluster/fenced` (use `vlib_stats_add_gauge`).
  - The input node is registered with `udp_register_dst_port (vm, port, cgnat_cluster_input_node.index, 1)`. On a HELLO it stores `last_rx`, the peer fields and the epoch with plain stores; the process reads them.
  - Ignore messages whose version != 1. Messages from node_id == own are duplicate-node-id.
  - Ready rules, which Task 5 completes:
    - **starting:** for one dead-interval after the cluster is enabled, not ready and translating nothing (drop counter `not-ready`)
    - **alone:** no peer heard by then → ready
    - **incumbent:** once ready, stay ready unless fenced or the configs mismatch
    - **resync:** a node that becomes non-starting while the peer is alive and ready resyncs before it's ready (Task 5)
    - **simultaneous start:** both peers starting or not ready → the lower node-id becomes ready (the incumbent) and the higher one resyncs from it
- [ ] **Step 4: Run them to make sure they pass, and run the Phase 1 suite.** Expected: all pass, and `test_cgnat` is still 79.
- [ ] **Step 5: Commit** `"Cluster: config, HELLO on pair and probe paths, liveness, config hash"`.

### Task 2: Ownership, fencing, frozen ownership on mismatch

**Files:**
- Create: `src/plugins/cgnat/cgnat_owner.h`
- Modify: `cgnat_cluster.c`, `cgnat_api.c`, `cgnat.api`, `cgnat_cli.c`
- Test: `test/test_cgnat_cluster.py` (class `TestCgnatClusterOwner`)

**Interfaces:**
- Consumes: Task 1 state.
- Produces:
  - `u8 cgnat_cluster.active[2]` and `u8 n_active`: the active node ids. It's recomputed by the process, published with a release store, and frozen while `reason == config-mismatch`.
  - `static_always_inline u8 cgnat_owner_node (u32 in_fib_index, u32 in_addr);` uses rendezvous hashing: `score(n) = clib_xxhash (((u64) in_fib_index << 32 | in_addr) ^ (0x9e3779b97f4a7c15ULL * n))`, and the highest score wins. Clustering off → own id.
  - Active set = {nodes that are alive and ready, self included only if ready}. Fenced → {peer}. If it's empty while starting → {} (drop as `not-ready`). The Task 1 rules guarantee two live nodes never both hold an active set of only themselves.
  - `static_always_inline u32 cgnat_thread_for (u32 in_fib_index, u32 in_addr, u16 first_worker, u16 n_workers);` generalises Phase 1's `cgnat_owner_thread`, which now calls it with the local values. It's used to address the peer's threads.
  - API `cgnat_cluster_owner (in_vrf, in_addr)` → node_id.
  - Fencing: pair path dead and any other path alive and own id > peer id → `fenced = 1`, not ready, reason "fenced".

- [ ] **Step 1: Write the failing tests.**

```python
def test_owner_alone_is_self(self):         # 256 subscribers -> all owner 1
def test_owner_split_with_peer(self):       # peer HELLO ready -> owners over 256 subscribers: both 1 and 2 appear, each between 96 and 160
def test_owner_peer_not_ready(self):        # peer HELLO alive but ready=0 -> all owner 1
def test_fence_higher_id(self):             # node_id=2, peer=1: probe path HELLOs keep coming, pair HELLOs stop -> fenced, not ready, all owner 1 (peer)
def test_no_fence_lower_id(self):           # node_id=1, same situation -> not fenced, ready, all owner 1 (self)
def test_takeover_when_all_paths_dead(self):# peer silent everywhere -> owner self for all, ready
def test_mismatch_freezes_ownership(self):  # peer ready (split) then peer hash changes -> owners unchanged from before, not ready
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass (both suites); commit `"Cluster: rendezvous ownership, fencing, frozen ownership on mismatch"`.

### Task 3: Steering over the pair link

**Files:**
- Create: `src/plugins/cgnat/cgnat_steer.c` (the encap helper, plus the steered node variants `cgnat-in2out-steered`, `cgnat-out2in-steered` and `cgnat-hairpin-steered`)
- Modify: `cgnat_in2out.c`, `cgnat_out2in.c` (owner-node check before the owner-thread check), `cgnat_cluster_input.c` (STEER decap), `cgnat_inlines.h`
- Test: `test/test_cgnat_cluster.py` (class `TestCgnatClusterSteer`)

**Interfaces:**
- Consumes: `cgnat_owner_node`, `cgnat_cluster_alloc`/`send`.
- Produces:
  - `#define CGNAT_NEXT_STEER ((u32) ~1)`: the nodes return it when the owner is the peer.
  - `cgnat_dispatch` gains a steer bucket: those buffers are encapsulated in place (`vlib_buffer_advance` negative, 52 bytes of headroom) and sent.
  - Nodes take the rx fib from the receive interface. Steered variants instead take it from `vnet_buffer (b)->sw_if_index[VLIB_TX]`, set by decap from `table_id`. The node functions grow `int is_steered`, and pass paths are unreachable when steered.
  - A steered packet whose owner is again not this node is dropped as `steer-loop`, never re-steered.
  - When owner == peer and the pair link is dead, the packet is dropped as `fenced`.
  - Order in in2out: map lookup, then owner node, then owner thread. In out2in: map lookup, reverse, owner node, owner thread. Hairpin: owner of the destination subscriber.
  - Counters: `/cgnat/steered-out`, `/cgnat/steered-in`.

- [ ] **Step 1: Write the failing tests.** The peer is ready, so ownership is split. Pick subscribers with `cgnat_cluster_owner`.

```python
def test_outbound_for_peer_steered(self):  # peer-owned subscriber sends on pg0 -> nothing on pg1; STEER on pg2: direction 0, table 0, inner == sent IP packet bytes (TTL unchanged)
def test_inbound_for_peer_steered(self):   # inbound to the pool ip:port in a peer subscriber's block -> STEER direction 1 on pg2
def test_steered_in_translated(self):      # inject STEER(direction 0) carrying an own subscriber's packet -> translated on pg1
def test_steered_out_translated(self):     # own subscriber has a mapping; inject STEER(direction 1) carrying the reply -> delivered on pg0
def test_steer_loop_dropped(self):         # inject STEER for a peer-owned subscriber -> dropped, counter steer-loop
def test_fenced_drops(self):               # fenced node: subscriber traffic -> dropped, counter fenced
def test_steer_large_packet_fragments_and_reassembles(self): # pg2 mtu 1500: 1472-byte UDP from a peer subscriber -> outer fragments on pg2; inject those fragments back as STEER for an own subscriber -> one translated packet on pg1
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass (both suites, including 2-worker variants `vpp_worker_count = 2` for this class); commit `"Cluster: steer non-owned packets to the owner over the pair link"`.

### Task 4: Session sync stream (records, batching, ack, retransmit, apply)

**Files:**
- Create: `src/plugins/cgnat/cgnat_sync.h`, `cgnat_sync.c` (per-thread streams and batch building, flush via interrupt node `cgnat-sync-flush`, retransmit, the apply node `cgnat-sync-worker` for SYNC/ACK on the target thread)
- Modify: `cgnat.h` (session gains `u8 warm`, `f64 last_synced`; per-thread stream state), `cgnat_session.c` (hooks), `cgnat_in2out.c`, `cgnat_out2in.c` (refresh/class-change hooks after touch), `cgnat_expire.c` (warm grace), `cgnat_cluster_input.c` (SYNC/ACK handoff by `dst_thread`/`src_thread`)
- Test: `test/test_cgnat_cluster.py` (class `TestCgnatClusterSync`)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `void cgnat_sync_session (cgnat_per_thread_t *t, u32 thread_index, cgnat_session_t *s, u8 op);` emits only if the cluster is enabled, the peer is alive and this node owns the subscriber.
  - It's called on: session create (upsert), class change (upsert), touch when `now - last_synced >= refresh_interval` (upsert), and free (delete).
  - Records go to the peer thread `cgnat_thread_for (…, peer_first_worker, peer_n_workers)`, one stream per (local thread, peer thread).
  - CLI `cgnat cluster window <n>` (default 1024) for tests and tuning.
  - Streams: next seq, `u32 *unacked` (buffer copies, `vlib_buffer_copy`) with send times, highest acked. Window 1024; overflow → drop the oldest, set `want_resync_peer` (sent as `want_resync` in HELLO), count `sync-overflow`.
  - Retransmit unacked packets older than 50 ms on each flush tick.
  - Apply an upsert: find the local map by (in_table_id, in_addr) → else `sync-unknown-map`. Then sub_get create → mapping by (in, in_port, proto): create with the given out_addr/out_port if absent → session upsert (state, class, `last_heard = now - idle_ds/10`, `warm = 1`). Apply a delete: free if present.
  - ACK: the receiver acks the highest contiguous seq per stream once per flush tick when something arrived. The sender frees acked copies.
  - A local touch of a warm session clears `warm`.
  - Expiry: `timeout + (warm ? refresh_interval : 0)`.
  - Session dump gains `bool warm`. Counters: `/cgnat/sync/records-out`, `records-in`, `retransmits`, `sync-overflow`, `sync-unknown-map`.

- [ ] **Step 1: Write the failing tests.** The peer is ready; use own-owned subscribers unless stated.

```python
def test_create_emits_upsert(self):          # flow -> SYNC on pg2 within 50ms, one record op 1 with the session's in/out/remote tuple, proto, class
def test_batching(self):                     # 40 flows sent in one burst -> SYNC packets carry > 1 record each, total 40 records
def test_retransmit_until_ack(self):         # no ACK -> same seq seen again after >= 50ms; inject ACK(seq) -> no further copies of it within 300ms
def test_delete_on_expiry(self):             # udp timeout 1s -> after expiry a record op 2 for that session
def test_apply_upsert_warm(self):            # inject SYNC upsert for a peer-owned subscriber -> cgnat_session_dump shows it warm with the given out port; an ACK for that stream goes out on pg2
def test_apply_delete(self):                 # then inject delete -> gone
def test_record_for_unknown_map_rejected(self): # upsert with in_table_id 77 -> no session, counter sync-unknown-map
def test_window_overflow_triggers_resync(self): # window shrunk via CLI "cgnat cluster window 8", 20 flows, no ACKs -> sync-overflow > 0, HELLO want_resync bit set, VPP alive, all 20 sessions still local
def test_warm_grace(self):                   # warm session with udp timeout 1s, refresh 3s -> still present after 2s, gone after 5s
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass (both suites, plus a 2-worker variant where record dst_thread follows the peer's advertised workers); commit `"Cluster: reliable batched session sync with warm copies"`.

### Task 5: Resync, failover, failback

**Files:**
- Modify: `cgnat_sync.c` (bulk resync: chunked walk per thread through the `cgnat-sync-flush` node, RESYNC_END per thread), `cgnat_cluster.c` (requests resync when the peer appears or its epoch changes, or when the peer's HELLO has `want_resync`; ready only after RESYNC_END from all `n_src_threads`; resets streams on a new peer epoch)
- Test: `test/test_cgnat_cluster.py` (class `TestCgnatClusterFailover`)

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - Ready condition: alone, or incumbent (already ready, not fenced, hash equal), or resync from the current peer epoch complete.
  - A node that leaves `starting` and finds the peer alive and ready sends RESYNC_REQ and reports `resyncing`. Its active set is {peer} until RESYNC_END from all `n_src_threads` arrives; then it's ready and ownership splits.
  - The incumbent never resyncs from a joining peer. It answers the peer's RESYNC_REQ.
  - A new peer epoch makes the peer not ready until its HELLO says ready.
  - A resync walk sends every session the node holds (owned or warm), up to 2048 records per thread per run, re-arming itself like the expiry walk.

- [ ] **Step 1: Write the failing tests.** The scapy peer plays node 2.

```python
def test_resync_request_answered(self):     # 30 own sessions; inject RESYNC_REQ -> SYNC upserts covering all 30, then RESYNC_END per thread with n_src_threads
def test_joining_node_resyncs(self):    # peer HELLOs (ready) already flowing when cgnat_cluster_set runs -> after starting: RESYNC_REQ on pg2, reason "resyncing", all owners = peer; inject RESYNC_END (n_src_threads=1) -> ready, owners split
def test_incumbent_stays_ready(self):   # alone and ready; peer appears ready=0 -> still ready, no RESYNC_REQ sent, all owners self
def test_simultaneous_start(self):      # peer HELLOs (node 2, ready=0) present during starting -> we (node 1) become ready, send no RESYNC_REQ
def test_failover_uses_warm_copy(self):     # peer ready (split); inject SYNC upsert for a peer-owned subscriber's session; stop peer HELLOs; after 0.7s the reply to that session's out port on pg1 is translated to the right inside host:port on pg0 (same public port)
def test_failback_after_resync(self):       # alone, owning all; peer appears ready=0 and sends RESYNC_REQ -> we answer (SYNC + RESYNC_END), owners still all self; peer HELLO ready=1 -> owners split
def test_peer_fast_restart_resets_streams(self): # peer ready; new epoch in HELLO with no dead gap -> streams reset (next SYNC seq starts at 0), we keep owning all until peer ready again
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass; commit `"Cluster: bulk resync, failover from warm copies, failback after resync"`.

### Task 6: Two-VPP integration harness and kill tests

**Files:**
- Create: `lab/ha/up.sh`, `lab/ha/down.sh`, `lab/ha/vpp-a.conf`, `lab/ha/vpp-b.conf`, `lab/ha/watch.sh` (stands in for BGP: withdraws a node's ECMP next hop when it isn't ready or is unreachable), `lab/ha/test-failover.sh`, `lab/ha/README.md`

**Interfaces:**
- **Topology (on vppdev).** Network namespaces `cli` (100.64.0.10/24), `rtr` and `srv` (198.51.100.10/24). Linux bridges `br-in` (10.1.0.0/24) and `br-out` (10.2.0.0/24). Two release-build VPPs, A (node 1) and B (node 2), each with three interfaces:
  - a tap on br-in (.2 / .3)
  - a tap on br-out (.2 / .3)
  - a memif pair link (10.255.0.1 / .2), plus probe paths over the br-in taps
- **Routing in `rtr`:**
  - `ip rule iif veth-cli table 100`
  - table 100 default via 10.1.0.2 and 10.1.0.3 (multipath, `fib_multipath_hash_policy=1`)
  - main table 192.0.2.0/28 via 10.2.0.2 and 10.2.0.3 (multipath)
  - routes back to 100.64.0.0/24 and 198.51.100.0/24 are connected
- **VPP config:**
  - map `100.64.0.0/24 → 192.0.2.0/28`
  - default route via 10.2.0.1 (rtr), and 100.64.0.0/24 via 10.1.0.1 (rtr)
- `watch.sh` polls `show cgnat cluster` every 100 ms per node and removes or adds that node's next hops in both rtr tables.

- [ ] **Step 1:** Write `lab/ha/test-failover.sh`. Its pass criteria print `PASS`/`FAIL` lines:
  - (a) 8 parallel iperf3 TCP streams for 60 s, plus 16 socat UDP echo flows sending 10 pps for 60 s
  - (b) at t=15s `kill -9` VPP-B; at t=35s restart VPP-B with the same config; at t=50s run `show cgnat cluster` on both and check both ready
  - (c) PASS needs all of the following:
    - every iperf3 stream completes without error and with no reconnect (one TCP connection per stream for the whole run, checked with `ss` on `srv`)
    - every UDP flow keeps the same public IP:port as seen on `srv`, before kill, after kill and after failback
    - UDP loss per flow ≤ 2 s worth around each event
    - no mapping change: `cgnat_forward` is unchanged
    - steered-out > 0 on both nodes before the kill (asymmetric paths really happened)
- [ ] **Step 2:** Run it before Tasks 1–5 are deployed (Phase 1 plugin, no cluster). Expected: FAIL. Streams via B reset on the kill and public ports change.
- [ ] **Step 3:** Run it with the Phase 2 build. Expected: PASS. Record the measured failover gap, failback gap, sync records/s and the pair-link bandwidth.
- [ ] **Step 4: Commit** `"HA lab: two-VPP namespace harness, kill/restore test"` with the result log in `lab/ha/results-<date>.txt`.

### Task 6a: Data-path speed (before the lab)

**Files:** `cgnat_in2out.c`, `cgnat_out2in.c`, `cgnat_session.[ch]`, `bench/`
- Prefetch the bihash bucket for packet i+N while processing packet i (`clib_bihash_hash_16_8`, `clib_bihash_prefetch_bucket_16_8`, `clib_bihash_search_inline_with_hash_16_8`).
- One lookup per packet in each direction: add a 5-tuple session index (`clib_bihash_24_8`, keyed on the inside tuple and on the outside tuple), with the mapping lookup only on a miss.
- Handoff: size the frame queues and batch per destination thread.
- Pass criteria:
  - `bench/run-all.sh` before and after: the 1-worker 15k-flow case at ≥ 2× today's 1.54 Mpps
  - the 4-worker 1M case scales at ≥ 0.75 × per-worker rate × workers
  - no handoff-queue-full drops below the forwarding rate
  - all tests still pass

### Task 8: Roll out and prove on cgnat-1 and cgnat-2 (prox-hv01, au-syd-0 production edge)

- cgnat-2 is a new VM, a twin of cgnat-1. Both get:
  - DPDK virtio-pci with multiqueue (queues = workers)
  - vCPUs pinned on one NUMA node, hugepages, `cpu { main-core / corelist-workers }` matching the pins
  - a pair link (a dedicated VLAN between them), with the probe paths on the inside and outside VLANs
- core0 changes:
  - the pool routes over both nodes' outside links, with ECMP
  - the CGNAT VRF default over both inside links, with ECMP
  - each node withdrawn when it isn't ready
  - through `commit confirmed`, with a backup first
- Prove it with the test line SVC-0004 on CGNAT plus blaster load:
  - kill each node mid-download
  - zero established-session loss, and the same public IP:port
  - clean failback, and the cgnatd ledger unchanged
- Record the numbers.

### Task 7: Docs and README

**Files:**
- Modify: `docs/config.md` (cluster section: config, wire protocol, ready semantics, what the operator's routing should watch, MTU guidance ≥ 1600 on the pair link), `README.md` (status, HA section, numbers from Task 6 and the Phase 1 bench)

- [ ] **Step 1:** Write the docs. Every value they quote must come from the code or from a result log.
- [ ] **Step 2: Commit** `"Docs: cluster configuration and HA results"`.
