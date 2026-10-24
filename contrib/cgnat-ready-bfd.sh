#!/bin/bash
# Example routing glue: keep this node's BFD sessions to the router admin-up
# only while the cgnat node reports ready.  The router (static routes with
# BFD-checked next hops) then sends traffic only to ready nodes, and
# withdraws a node within the BFD detect time when it stops, restarts,
# resyncs or fences.
#
#   cgnat-ready-bfd.sh "interface outside local-addr A peer-addr B" ...
#
# Each argument names one existing `bfd udp session` (create them in VPP's
# startup config, followed by `... set-flags ... admin down`).
SOCK=${VPPCTL_SOCK:-/run/vpp/cli.sock}
VPPCTL=${VPPCTL:-vppctl}
state=""
while true; do
  want=down
  if out=$(timeout 0.5 $VPPCTL -s $SOCK show cgnat cluster 2>/dev/null) &&
     echo "$out" | head -1 | grep -q ": ready,"; then
    want=up
  fi
  if [ "$want" != "$state" ]; then
    for s in "$@"; do
      $VPPCTL -s $SOCK bfd udp session set-flags $s admin $want >/dev/null 2>&1
    done
    logger -t cgnat-ready-bfd "cgnat ready=$( [ $want = up ] && echo yes || echo no ): bfd admin $want"
    state=$want
  fi
  sleep 0.1
done
