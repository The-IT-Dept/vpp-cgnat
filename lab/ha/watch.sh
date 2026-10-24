#!/bin/bash
# Stand-in for the operator's BGP: a node's ECMP next hops are present in
# the router only while that node reports ready.  Polls every 100 ms.
cd "$(dirname "$0")"; . ./common.sh
LOG=${1:-$RUN/watch.log}
last=""
while true; do
  set_in=""; set_out=""; ready=""
  for n in a b; do
    idx=$([ $n = a ] && echo 2 || echo 3)
    if out=$(timeout 0.5 $VPPDIR/bin/vppctl -s $RUN/$n.sock show cgnat cluster 2>/dev/null) &&
       { { [ ! -s $RUN/mode ] && echo "$out" | grep -q "disabled (alone, ready)"; } ||
         echo "$out" | head -1 | grep -q ": ready,"; }; then
      ready="$ready$n"
      set_in="$set_in nexthop via 10.1.0.$idx dev br-in"
      set_out="$set_out nexthop via 10.2.0.$idx dev br-out"
    fi
  done
  if [ "$ready" != "$last" ] && [ -n "$ready" ]; then
    NS rtr ip route replace default table 100 $set_in
    NS rtr ip route replace 192.0.2.0/28 $set_out
    echo "$(date +%T.%N | cut -c1-12) ready=$ready" >> $LOG
    last=$ready
  fi
  sleep 0.1
done
