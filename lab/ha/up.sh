#!/bin/bash
# Bring up the HA lab: namespaces, bridges, ECMP router, two VPPs (A, B).
#   up.sh [nocluster]      (nocluster: run both nodes without the pair, for the "before" run)
set -e
cd "$(dirname "$0")"; . ./common.sh
./down.sh >/dev/null 2>&1 || true
mkdir -p $RUN/a $RUN/b /run/vpp
for ns in cli rtr srv; do ip netns add $ns; NS $ns ip link set lo up; done
NS rtr sysctl -qw net.ipv4.ip_forward=1 net.ipv4.fib_multipath_hash_policy=1 \
  net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
NS rtr ip link add br-in type bridge; NS rtr ip link add br-out type bridge
NS rtr ip addr add 10.1.0.1/24 dev br-in; NS rtr ip addr add 10.2.0.1/24 dev br-out
# fixed bridge MACs: a Linux bridge otherwise takes its MAC from its ports
# and changes it when a node's taps disappear (a real router doesn't)
NS rtr ip link set br-in address 02:00:00:00:01:01
NS rtr ip link set br-out address 02:00:00:00:02:01
NS rtr ip link set br-in up; NS rtr ip link set br-out up
ip link add cli0 netns cli type veth peer name rtr-cli netns rtr
ip link add srv0 netns srv type veth peer name rtr-srv netns rtr
NS cli ip addr add 100.64.0.10/24 dev cli0; NS cli ip link set cli0 up
# more subscribers (100.64.0.11-.29) so both nodes own some
for i in $(seq 11 29); do NS cli ip addr add 100.64.0.$i/24 dev cli0; done
NS cli ip route add default via 100.64.0.1
NS srv ip addr add 198.51.100.10/24 dev srv0; NS srv ip link set srv0 up
NS srv ip route add default via 198.51.100.1
NS rtr ip addr add 100.64.0.1/24 dev rtr-cli; NS rtr ip link set rtr-cli up
NS rtr ip addr add 198.51.100.1/24 dev rtr-srv; NS rtr ip link set rtr-srv up
for d in cli0; do NS cli ethtool -K $d tx off >/dev/null 2>&1 || true; done
for d in srv0; do NS srv ethtool -K $d tx off >/dev/null 2>&1 || true; done
# subscriber traffic is policy-routed through the CGNAT pair
NS rtr ip rule add iif rtr-cli lookup 100

start_node() { # name idx pair main workers memif_role cluster-section
  local n=$1
  # the cluster goes in startup.conf so it is on (starting, not ready)
  # before any interface or map exists: the node never translates alone
  sed -e "s|@RUN@|$RUN|g" -e "s|@N@|$n|g" -e "s|@MAIN@|$4|" -e "s|@WORKERS@|$5|" \
    -e "s|@CLUSTER@|$7|" vpp.conf.in > $RUN/$n.conf
  sed -e "s|@N@|$n|g" -e "s|@IDX@|$2|g" -e "s|@PAIR@|$3|" -e "s|@MEMIF_ROLE@|$6|" \
    node.cli.in > $RUN/$n.cli
  setsid $VPPDIR/bin/vpp -c $RUN/$n.conf > $RUN/$n.stdout 2>&1 < /dev/null &
  echo $! > $RUN/$n.pid
}
if [ "$1" = nocluster ]; then CA=""; CB=""; else
  CA='cluster { node-id 1 local 10.255.0.1 peer 10.255.0.2 path local 10.1.0.2 peer 10.1.0.3 }'
  CB='cluster { node-id 2 local 10.255.0.2 peer 10.255.0.1 path local 10.1.0.3 peer 10.1.0.2 }'
fi
echo "$CA$CB" > $RUN/mode
start_node a 2 1 1 2 master "$CA"
start_node b 3 2 3 4 slave "$CB"
for i in $(seq 50); do vppctl_a show version >/dev/null 2>&1 && vppctl_b show version >/dev/null 2>&1 && break; sleep 0.2; done
sleep 2
NS rtr ip route replace default table 100 nexthop via 10.1.0.2 dev br-in nexthop via 10.1.0.3 dev br-in
NS rtr ip route replace 192.0.2.0/28 nexthop via 10.2.0.2 dev br-out nexthop via 10.2.0.3 dev br-out
echo "lab up"; vppctl_a show cgnat cluster; vppctl_b show cgnat cluster
