# vpp-cgnat Phase 1: build environment and single-node plugin

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A VPP 26.06 plugin, `cgnat`, that does deterministic port-block NAT44 on one node, with EIM mapping, filtering, hairpinning, state-aware timers and a per-subscriber cap. It must be correct across workers, configured via startup.conf, CLI and binary API, and observable via the stats segment. Everything is proven with VPP `make test` on a Linux build VM.

**Architecture:**
- **Subscriber identity:** (inside fib index, inside IPv4).
- **The map:** a formula identical to det44's, giving each subscriber an outside IP and a contiguous port block, in both directions.
- **Workers:** each subscriber's state lives on one worker, `hash(subscriber) % n_workers`. Both directions find that worker without shared state: in2out from the inside source, out2in from the reverse formula on outside IP and port. Packets are handed off accordingly.
- **Two tables per worker:** EIM mappings (inside ip:port:proto → outside port) and sessions (mapping + remote ip:port, with TCP state and timers).
- **Expiry:** a per-worker process walks protocol LRU lists.

**Tech Stack:** C (VPP 26.06 plugin API, bihash, vlib nodes, feature arcs, shallow virtual reassembly), VPP `.api`/vppapigen, Python VPP test framework (scapy).

**Spec:** `docs/superpowers/specs/2026-10-24-cgnat-ha-design.md` (read the Rulings section).

## Global Constraints

- VPP tag **v26.06**, C, in-tree build: the repo's `src/plugins/cgnat` is symlinked into `<vpp>/src/plugins/cgnat`.
- Apache-2.0 header on every source file. Symbol and node prefix `cgnat_` / `cgnat-`. API messages prefixed `cgnat_`.
- **Formula, verbatim from det44:**
  - `ratio = inside_size / outside_size`, a power of two, and at least 1
  - `ports_per_sub = (65536 - 1024) / ratio`
  - `outside = outside_base + offset / ratio`
  - `port_lo = 1024 + ports_per_sub * (offset % ratio)`
  - `port_hi = port_lo + ports_per_sub - 1`
  - `offset = inside - inside_base`
- **Subscriber identity** is (inside fib index, inside address). Maps in different inside VRFs may overlap; maps in the same inside VRF may not.
- **Defaults** (configurable):
  - timeouts: tcp-established 7440 s, tcp-transitory 240 s, udp 300 s, icmp 60 s
  - sessions-per-subscriber: 1000
  - filtering: address-dependent
- Changing a map with live sessions is refused (`del` then `add`). Deleting a map flushes its sessions.
- Untranslatable traffic is dropped and counted, never leaked. That covers no map, no mapping, filtered, cap reached and block exhausted.
- Clustering, sync and the config hash are Phase 2. Leave no hooks you'd have to guess at; keep `cgnat_main_t` extensible.

## Review Focus

1. Inside traffic from an address in no map: drop with `no-map`; never forward untranslated. (Test: Task 3, `test_unmapped_inside_dropped`.)
2. Unsolicited or scanning inbound to a pool IP:port with no mapping: drop with `no-mapping`, and create no state. (Test: Task 3, `test_unsolicited_inbound_dropped`.)
3. Fragmented UDP: a non-first fragment has no ports, so all fragments must translate consistently (shallow virtual reassembly, as det44 does). (Test: Task 3, `test_fragments_translated`.)
4. After a mapping expires, the same inside port gets the same outside port again (deterministic first choice). (Test: Task 7, `test_same_port_after_expiry`.)
5. Deleting a map with live sessions: sessions are flushed, counters return to 0, and later packets drop with `no-map` without crashing. (Test: Task 9, `test_map_delete_flushes_sessions`.)

---

### Task 1: Build/test VM, repo skeleton, a plugin that loads

**Files:**
- Create: `src/plugins/cgnat/CMakeLists.txt`, `src/plugins/cgnat/cgnat.h`, `src/plugins/cgnat/cgnat.c`
- Create: `scripts/link-into-vpp.sh`, `scripts/test.sh`, `test/test_cgnat.py`, `LICENSE` (Apache-2.0), `README.md`

**Interfaces:**
- Produces:
  - `typedef struct { ... } cgnat_main_t; extern cgnat_main_t cgnat_main;` in `cgnat.h`
  - `scripts/test.sh <TestName>` runs one VPP test against this repo's tests

- [ ] **Step 1: Provision the VM `vppdev` on prox-hv01 (root@157.20.113.249)**
  - Proxmox VM id **9197**, Ubuntu 24.04 cloud image.
  - Sizing: 8 vCPU, 16 GiB RAM, 100 GiB disk on pool `store`, NIC on `vmbr0`.
  - Management IP: the next free address in 157.20.113.0/24 (check NetBox; use .112 if free), gateway 157.20.113.1.
  - Root SSH: your Mac's key.
  - Enable 1024 × 2 MiB hugepages persistently in the kernel cmdline.

- [ ] **Step 2: VPP checkout and baseline build**
  - On vppdev: `git clone https://github.com/FDio/vpp ~/vpp && cd ~/vpp && git checkout v26.06 && make install-dep && make build`.
  - Expected: `build-root/build-vpp_debug-native` exists, with no build errors.

- [ ] **Step 3: Prove the test framework with a stock test**
  - Run: `cd ~/vpp && make test-debug TEST=test_det44`
  - Expected: all TestDET44 tests PASS. This is the baseline that later tasks are compared against.

- [ ] **Step 4: Repo skeleton**
  - Copy the repo to vppdev at `~/vpp-cgnat` (rsync from the Mac).
  - `scripts/link-into-vpp.sh` runs `ln -sfn ~/vpp-cgnat/src/plugins/cgnat ~/vpp/src/plugins/cgnat`.
  - `scripts/test.sh` runs `cd ~/vpp && make test-debug TEST="$1" EXTERN_TESTS=$HOME/vpp-cgnat/test`.

- [ ] **Step 5: Write the failing test**

```python
class TestCgnatPlugin(VppTestCase):
    def test_plugin_loaded(self):
        out = self.vapi.cli("show plugins")
        self.assertIn("cgnat_plugin.so", out)
```

- [ ] **Step 6: Run it to make sure it fails**
  - Run: `scripts/test.sh test_cgnat`
  - Expected: FAIL, `cgnat_plugin.so` not in the output.

- [ ] **Step 7: Implement a minimal plugin**
  - `VLIB_PLUGIN_REGISTER` with description `"CGNAT: deterministic port blocks, HA pair (vpp-cgnat)"`.
  - `cgnat_init` zeroes `cgnat_main`.
  - CMake: `add_vpp_plugin(cgnat SOURCES cgnat.c)`.

- [ ] **Step 8: Run it**
  - Run: `scripts/link-into-vpp.sh && cd ~/vpp && make build && ~/vpp-cgnat/scripts/test.sh test_cgnat`
  - Expected: PASS.

- [ ] **Step 9: Commit**
  - `git add -A && git commit -m "Skeleton: cgnat plugin loads; vppdev build/test scripts"`

### Task 2: Maps, the formula, and forward/reverse lookup (CLI + API)

**Files:**
- Create: `src/plugins/cgnat/cgnat_map.h`, `cgnat_map.c`, `cgnat.api`, `cgnat_api.c`, `cgnat_cli.c`
- Modify: `cgnat.h`, `CMakeLists.txt`
- Test: `test/test_cgnat.py` (class `TestCgnatMap`)

**Interfaces:**
- Produces:
  - `typedef struct { u32 in_fib_index, out_fib_index; ip4_address_t in_base, out_base; u8 in_plen, out_plen; u32 ratio; u16 ports_per_sub; } cgnat_map_t;`
  - `int cgnat_map_add_del (u32 in_vrf, ip4_address_t *in_pfx, u8 in_plen, u32 out_vrf, ip4_address_t *out_pfx, u8 out_plen, int is_add);` returns 0 or a `VNET_API_ERROR_*` code
  - `cgnat_map_t *cgnat_map_by_inside (u32 in_fib_index, ip4_address_t *a);` and `cgnat_map_t *cgnat_map_by_outside (u32 out_fib_index, ip4_address_t *a);`, each returning NULL if none
  - `void cgnat_forward (cgnat_map_t *m, ip4_address_t *in, ip4_address_t *out, u16 *port_lo, u16 *port_hi);`
  - `int cgnat_reverse (cgnat_map_t *m, ip4_address_t *out, u16 out_port, ip4_address_t *in);` returns 0, or -1 if the port is below 1024
  - API: `cgnat_map_add_del`, `cgnat_map_dump`/`details`, `cgnat_forward`/`reply` (in_vrf, in_addr → out_addr, port_lo, port_hi), `cgnat_reverse`/`reply` (out_vrf, out_addr, out_port → in_vrf, in_addr)
  - CLI:
    - `cgnat map add|del inside <pfx> [inside-vrf <n>] outside <pfx> [outside-vrf <n>]`
    - `show cgnat maps`
    - `show cgnat lookup forward <addr> [inside-vrf <n>]`
    - `show cgnat lookup reverse <addr>:<port> [outside-vrf <n>]`

- [ ] **Step 1: Write the failing tests** (values from our production pool)

```python
def test_forward_matches_det44(self):   # 100.64.0.0/23 -> 157.20.113.160/28
    self.vapi.cgnat_map_add_del(is_add=1, in_addr="100.64.0.0", in_plen=23, out_addr="157.20.113.160", out_plen=28)
    r = self.vapi.cgnat_forward(in_vrf=0, in_addr="100.64.0.5")
    self.assertEqual((str(r.out_addr), r.port_lo, r.port_hi), ("157.20.113.160", 11104, 13119))
    r = self.vapi.cgnat_forward(in_vrf=0, in_addr="100.64.1.255")   # offset 511
    self.assertEqual((str(r.out_addr), r.port_lo, r.port_hi), ("157.20.113.175", 1024 + 2016*31, 1024 + 2016*32 - 1))
def test_reverse_inverts_forward(self):  # for every offset 0..511 and its lo/hi port
def test_overlapping_vrfs(self):         # same inside /23 in vrf 1 -> .160/28 and vrf 2 -> .176/28; forward differs by vrf; reverse returns the right vrf
def test_reject_overlap_same_vrf(self):  # second add of 100.64.1.0/24 in vrf 0 -> retval != 0
def test_reject_bad_ratio(self):         # inside /28 -> outside /23 (ratio < 1) -> retval != 0
def test_del_removes(self):              # del then forward -> retval != 0
```

- [ ] **Step 2: Run them to make sure they fail**
  - Run: `scripts/test.sh test_cgnat.TestCgnatMap`
  - Expected: FAIL (unknown API).

- [ ] **Step 3: Implement**
  - Maps live in a pool with per-fib vectors for lookup. Sizes are small (tens of maps), so a linear scan per fib is fine.
  - VRF ids map to fib indices with `fib_table_find_or_create_and_lock`.

- [ ] **Step 4: Run them to make sure they pass**
  - Expected: PASS.

- [ ] **Step 5: Commit**
  - `git commit -am "Maps: det44 formula, VRF-keyed forward/reverse, CLI + API"`

### Task 3: Translation for UDP/TCP with EIM mappings (single worker)

**Files:**
- Create: `cgnat_session.h`, `cgnat_session.c` (tables), `cgnat_in2out.c`, `cgnat_out2in.c` (nodes), `cgnat_inlines.h`
- Modify: `cgnat.c` (feature enable), `cgnat_cli.c`, `cgnat.api` (interface feature)
- Test: `TestCgnatTranslate`

**Interfaces:**
- Consumes: Task 2 lookups.
- Produces:
  - Per-worker tables in `cgnat_per_thread_t`:
    - `mapping` keyed `{in_fib, in_addr, in_port, proto}` and `{out_fib, out_addr, out_port, proto}`, giving `cgnat_mapping_t {in_*, out_port, n_sessions, ...}`
    - `session` keyed `{mapping_index, remote_addr, remote_port}`, giving `cgnat_session_t {state, last_heard, lru_index}`
  - `u16 cgnat_pick_port (cgnat_per_thread_t *t, cgnat_map_t *m, ip4_address_t *out, u16 lo, u16 hi, u16 in_port, u8 proto);` returns the port, or 0 if the block is exhausted. First choice is `lo + (in_port % (hi - lo + 1))`, then linear probe within [lo, hi].
  - Feature arcs: `cgnat-in2out` on ip4-unicast for inside interfaces, `cgnat-out2in` for outside, both after `ip4-sv-reassembly-feature`.
  - API/CLI: `cgnat_interface_add_del_feature` (sw_if_index, is_inside); CLI `set interface cgnat in|out <intf> [del]`.
  - Drop counters (node errors): `no-map`, `no-mapping`, `filtered`, `cap`, `exhausted`.

- [ ] **Step 1: Write the failing tests** (pg0 inside, pg1 outside, map 10.0.0.0/24 → 192.0.2.0/30)

```python
def test_udp_out_and_back(self):        # in2out src rewritten to forward(in).out and port in [lo,hi]; reply out2in restores in addr/port; checksums valid
def test_tcp_out_and_back(self):        # SYN/SYN-ACK/ACK through; same assertions
def test_eim_same_port_any_dest(self):  # same in ip:port to two different remotes -> same outside port
def test_unmapped_inside_dropped(self): # src 10.9.9.9 (no map) -> no packet on pg1; "no-map" counter == 1
def test_unsolicited_inbound_dropped(self): # to 192.0.2.1:2000 with no mapping -> nothing on pg0; "no-mapping" == 1; show cgnat sessions empty
def test_fragments_translated(self):    # UDP 3000-byte payload fragmented inside -> every fragment arrives outside translated, reassembles on the far side
```

- [ ] **Step 2: Run them to make sure they fail.**

- [ ] **Step 3: Implement**
  - bihash `16_8` for both mapping keys and the session key.
  - L4 checksums updated incrementally, as det44 does (`ip_csum_update`).
  - In this task, out2in allows a packet when a session exists for (mapping, remote addr, remote port), or the mapping exists and the remote addr matches any of its sessions. That is address-dependent filtering. Task 4 adds the mode switch.

- [ ] **Step 4: Run them to make sure they pass.**

- [ ] **Step 5: Commit**
  - `"Translation: UDP/TCP in2out/out2in with EIM mappings and drop counters"`

### Task 4: Filtering modes, port collisions, session cap, block exhaustion

**Files:**
- Modify: `cgnat_out2in.c`, `cgnat_session.c`, `cgnat_cli.c`, `cgnat.api`
- Test: `TestCgnatPolicy`

**Interfaces:**
- Produces:
  - `cgnat_set_filtering (u8 endpoint_independent)`, plus CLI `cgnat filtering address-dependent|endpoint-independent`
  - `cgnat_set_session_limit (u32 per_subscriber)`, plus CLI `cgnat sessions-per-subscriber <n>`
  - API: `cgnat_set_filtering`, `cgnat_set_session_limit`

- [ ] **Step 1: Write the failing tests**

```python
def test_address_dependent_blocks_new_remote(self):   # mapping to R1; inbound from R2 to same outside port -> dropped "filtered"; from R1 other port -> passes
def test_endpoint_independent_allows_any(self):       # after cgnat_set_filtering(1): inbound from R2 -> passes to the inside host
def test_collision_probes_within_block(self):         # two in ports with in_port % ports_per_sub equal -> different outside ports, both within [lo,hi]
def test_session_cap(self):                           # limit 3: 4th distinct flow from one subscriber -> dropped "cap"; other subscriber unaffected
def test_block_exhausted(self):                       # ratio giving ports_per_sub small (map 10.0.0.0/22 -> 192.0.2.0/32, ppsub 63): 64th distinct in port -> "exhausted"
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass; commit `"Policy: filtering modes, collision probing, per-subscriber cap, block exhaustion"`.

### Task 5: ICMP echo and ICMP errors

**Files:**
- Modify: `cgnat_in2out.c`, `cgnat_out2in.c`, `cgnat_inlines.h`
- Test: `TestCgnatIcmp`

- [ ] **Step 1: Write the failing tests**

```python
def test_echo_out_and_back(self):       # echo id treated as port: id rewritten into [lo,hi]; reply restored
def test_error_for_udp_flow(self):      # outside sends ICMP dest-unreach quoting the translated UDP packet -> delivered inside with outer dst and embedded src/port restored
def test_error_without_flow_dropped(self): # ICMP error quoting an unknown flow -> dropped "no-mapping"
```

- [ ] **Steps 2–5:** run and see it fail; implement (det44's ICMP handling in `det44_in2out.c`/`det44_out2in.c` is the reference); run and see it pass; commit `"ICMP: echo and error translation"`.

### Task 6: Hairpinning

**Files:**
- Modify: `cgnat_in2out.c`
- Test: `TestCgnatHairpin`

- [ ] **Step 1: Write the failing test**

```python
def test_hairpin_between_subscribers(self):  # A (10.0.0.2) sends to B's outside ip:port (B has a mapping, EIF on) -> delivered to B on pg0 with src = A's outside ip:port
```

- [ ] **Steps 2–5:** run and see it fail; implement (in in2out, a destination within any map's outside prefix in the same outside fib is run through the out2in lookup before forwarding); run and see it pass; commit `"Hairpinning"`.

### Task 7: State-aware timers and expiry

**Files:**
- Create: `cgnat_expire.c`
- Modify: `cgnat_session.c`, `cgnat_cli.c`, `cgnat.api`
- Test: `TestCgnatTimers`

**Interfaces:**
- Produces:
  - `cgnat_set_timeouts (u32 tcp_est, u32 tcp_trans, u32 udp, u32 icmp)` (API and CLI `cgnat timeouts ...`), with the defaults from Global Constraints
  - Per-worker LRU dlists per timeout class, and a process node `cgnat-expire` (1 s tick, at most 1024 frees per tick per worker).
  - TCP state goes to transitory on FIN from both sides, or on RST.
  - A mapping is freed when its last session goes.

- [ ] **Step 1: Write the failing tests** (set timeouts to 2 s / 2 s / 2 s / 2 s, then wait 4 s with `self.virtual_sleep`)

```python
def test_udp_expires(self):             # flow, sleep 4 -> "show cgnat sessions" empty, mapping gone
def test_tcp_fin_goes_transitory(self): # with tcp_est=60, tcp_trans=2: FIN/FIN-ACK both ways, sleep 4 -> session gone
def test_tcp_rst_goes_transitory(self):
def test_same_port_after_expiry(self):  # flow from in port P gets outside Q; expire; same P again -> same Q
def test_traffic_keeps_alive(self):     # udp=3: packets every 1 s for 6 s -> session still present
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass; commit `"Timers: state-aware expiry, mapping lifetime"`.

### Task 8: Multi-worker correctness

**Files:**
- Create: `cgnat_handoff.c`
- Modify: `cgnat_in2out.c`, `cgnat_out2in.c`, `cgnat.c`
- Test: `TestCgnatWorkers` with `vpp_worker_count = 2`, re-running Task 3's and Task 4's scenarios

**Interfaces:**
- Produces:
  - `u32 cgnat_owner_thread (u32 in_fib_index, ip4_address_t *in_addr);` returns `first_worker + hash % n_workers`, and is used by both directions.
  - out2in derives `in_addr` with `cgnat_reverse` before choosing the thread.
  - Handoff nodes `cgnat-in2out-handoff` and `cgnat-out2in-handoff` use `vlib_buffer_enqueue_to_thread`.

- [ ] **Step 1: Write the failing tests**

```python
class TestCgnatWorkers(TestCgnatTranslate):  # same tests, vpp_worker_count = 2
    vpp_worker_count = 2
def test_many_subscribers_spread(self):      # 64 subscribers x 4 flows each, out and back: every reply delivered; per-thread session counts both > 0
```

- [ ] **Steps 2–5:** run and see it fail (replies land on the wrong thread); implement; run and see it pass; commit `"Multi-worker: subscriber-owned threads, handoff both directions"`.

### Task 9: startup.conf, stats segment, session dump, map flush

**Files:**
- Modify: `cgnat.c` (`VLIB_CONFIG_FUNCTION (cgnat_config, "cgnat")`), `cgnat_api.c`, `cgnat_cli.c`, `cgnat_map.c`
- Create: `docs/config.md` (startup.conf, CLI and API reference)
- Test: `TestCgnatOps`

**Interfaces:**
- Produces:
  - startup.conf `cgnat { sessions-per-subscriber <n> timeouts { tcp-established <s> tcp-transitory <s> udp <s> icmp <s> } filtering address-dependent|endpoint-independent }`
  - Stats segment under `/cgnat/`:
    - simple counters `in2out-packets`, `out2in-packets`, `hairpin-packets`
    - gauges `sessions`, `mappings`, `subscribers` (summed across workers)
    - plus the node drop counters
  - API `cgnat_session_dump` (filter by in_vrf + in_addr, or all) → `cgnat_session_details {in_vrf, in_addr, in_port, out_addr, out_port, remote_addr, remote_port, proto, state, age}`
  - API `cgnat_get_status` → {maps, sessions, mappings, subscribers, filtering, limits, timeouts}
  - CLI `show cgnat sessions [subscriber <addr> [inside-vrf <n>]]`, `show cgnat status`

- [ ] **Step 1: Write the failing tests**

```python
def test_startup_conf_applied(self):        # extra_vpp_config sets limit 7, udp 11 -> cgnat_get_status reflects 7 and 11
def test_stats_counters(self):              # 5 flows out and back -> /cgnat/in2out-packets >= 5, /cgnat/sessions == 5 (statistics.get_counter)
def test_session_dump(self):                # dump shows the 5 sessions with the right in/out/remote tuples
def test_map_delete_flushes_sessions(self): # with live sessions, map del -> sessions/mappings gauges 0; next packet -> "no-map"; no crash
def test_map_change_refused_with_sessions(self): # add an overlapping map (same in vrf) while sessions live -> retval != 0
```

- [ ] **Steps 2–5:** run and see it fail; implement; run and see it pass; commit `"Ops: startup.conf, stats segment, session dump/status, map flush"`.

- [ ] **Final step:** run the whole suite twice:
  - `scripts/test.sh test_cgnat`
  - `cd ~/vpp && make test-debug TEST=test_det44`, to check we didn't disturb VPP
  - Expected: all PASS.
