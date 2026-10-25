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
#
# Run it independently of VPP (not bound to vpp.service) with
# Restart=always: when VPP restarts (a new pid, whose startup config
# recreates the sessions admin-down) it exits and starts afresh.  It
# retries until every set-flags succeeds.
SOCK=${VPPCTL_SOCK:-/run/vpp/cli.sock}
VPPCTL=${VPPCTL:-vppctl}
STATS=${VPP_GET_STATS:-vpp_get_stats}
# local state of the session "interface I local-addr A peer-addr B"
session_state() {
  set -- $1
  $VPPCTL -s $SOCK show bfd sessions 2>/dev/null | tr -d "\r" |
    awk -v l="$4" -v p="$6" '/IPv4 address/ {m = ($(NF-1) == l && $NF == p)}
	m && /Session state/ {print $(NF-1); exit}'
}

state=""
pid=""
while true; do
  want=down
  if out=$(timeout 0.5 $STATS dump /cgnat/cluster/ready 2>/dev/null) &&
     echo "$out" | grep -q "^1"; then
    want=up
  fi
  now=$(pidof -s vpp)
  # a new VPP incarnation (its sessions start admin-down): exit and let
  # systemd start us afresh, rather than carry state across restarts
  [ -n "$pid" ] && [ -n "$now" ] && [ "$now" != "$pid" ] && exit 0
  pid=$now
  if [ "$want" != "$state" ] && [ -n "$pid" ]; then
    ok=1
    for s in "$@"; do
      # admin up resets a session that is already up (the router sees a
      # flap): only bring up sessions that are admin-down
      [ $want = up ] && [ "$(session_state "$s")" != AdminDown ] &&
	[ -n "$(session_state "$s")" ] && continue
      out=$($VPPCTL -s $SOCK bfd udp session set-flags $s admin $want 2>&1)
      [ $? -ne 0 ] || [ -n "$out" ] && ok=0
    done
    if [ $ok = 1 ]; then
      logger -t cgnat-ready-bfd "cgnat ready=$( [ $want = up ] && echo yes || echo no ): bfd admin $want"
      state=$want
    fi
  fi
  sleep 0.1
done
