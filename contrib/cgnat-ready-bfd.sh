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
# Readiness comes from the stats segment (/cgnat/cluster/ready), which
# doesn't stop the workers the way a CLI command does.  The gauge is set
# while the cluster is enabled; a node without a cluster reads not-ready.
SOCK=${VPPCTL_SOCK:-/run/vpp/cli.sock}
VPPCTL=${VPPCTL:-vppctl}
STATS=${VPP_GET_STATS:-vpp_get_stats}
state=""
while true; do
  want=down
  if out=$(timeout 0.5 $STATS dump /cgnat/cluster/ready 2>/dev/null) &&
     echo "$out" | grep -q "^1"; then
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
