# Clock skew

## What wedged BFD

On 2026-10-27/28 both CGNAT nodes stopped transmitting BFD, after 56 h and 81 h
of uptime. Every core0 BFD session went down and the CGNAT had no default route
for about 2.75 days, until VPP was restarted.

- **The cause.** In VPP 26.06 each thread's vlib time drifts apart from the
  others as uptime grows (`clib_time_verify_frequency` ratchets a clock
  forward), and a barrier never pulls a worker that is ahead back to main
  (vppinfra 5c19169ae). The workers were 66.6 s (cgnat-1) and 71.5 s (cgnat-2)
  ahead of main.
- **Why BFD stopped.** Workers stamp each received control frame with their own
  clock, and main schedules transmits with its clock. Once a worker led main by
  more than the peer's transmit interval, every frame it received pushed the next
  transmit time beyond main's "now". VPP never transmitted again and sat in Init.

## The fix

Two VPP patches, applied by `scripts/apply-patches.sh` (see `patches/series`):

- `vpp-26.06-time-monotonic.patch` backports master 7d65ef4b8, which keeps each
  thread's time monotonic while it tracks the wall clock. This removes the drift.
  The same diff is on stable/2606 (8f426ed54, in no 26.06.x tag yet) and in
  v26.10. Drop the patch on a base that has it.
- `vpp-26.06-bfd-advertise-effective-tx.patch` puts every BFD timestamp on one
  clock, `CLOCK_MONOTONIC`, on every thread, so BFD no longer depends on the
  threads agreeing. bfd-process still sleeps on main's vlib clock, so ship it
  only together with the time patch.

The plugin does the same for everything one thread stamps and another compares:
HELLO liveness, the duplicate-id hold, resync progress and the resync walk
(see [config.md](config.md#paths-and-split-brain)). The tests put a worker
5 s ahead of main, or behind it, with `test time worker-skew <sec> [hold]`.

## Checking a node

```
vpp# show clock
...
Thread 1 offset 40.721768271 error -66.567121597
Thread 2 offset 40.408088059 error -66.132792203
```

`error` is main's last barrier release minus that thread's. Negative means the
worker is ahead of main. The numbers above are cgnat-1 when it wedged. On a
patched node it should stay within a few ms. A lead never heals by itself, so
alert on |error| above about 50 ms. That would have caught the incident about
two days before BFD wedged.

## Time sync on the nodes

Keep systemd-timesyncd. It steps the clock only for offsets over 0.4 s and slews
at no more than 500 ppm, and every thread handles both the same way. If chrony
replaces it, set `maxslewrate 5000` or lower and keep `makestep` at 0.5 s or
more. A slew of 0.2-1.8 % can be absorbed by one thread and slewed by another,
which leaves a lasting offset between them.
