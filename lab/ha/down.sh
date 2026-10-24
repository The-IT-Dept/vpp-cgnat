#!/bin/bash
cd "$(dirname "$0")"; . ./common.sh
pkill -f "$(dirname $0)/watch.sh" 2>/dev/null; pkill -f watch.sh 2>/dev/null
for n in a b; do [ -f $RUN/$n.pid ] && kill -9 $(cat $RUN/$n.pid) 2>/dev/null; done
pkill -9 -f "vpp -c $RUN/" 2>/dev/null
pkill -f iperf3 2>/dev/null; pkill -f udpflows.py 2>/dev/null
for ns in cli rtr srv; do ip netns del $ns 2>/dev/null; done
rm -f /run/vpp/memif.sock /run/vpp-ha/memif.sock
true
