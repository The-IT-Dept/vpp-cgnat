#!/bin/bash
# Single-node packet-generator benchmark for the cgnat plugin (release build).
# No NICs: VPP's pg generates inside->outside UDP; pg1 output just frees.
#
#   bench/pg-bench.sh <workers> [subs_bits] [ports]
#
# subscribers = 2^subs_bits inside addresses (100.64.0.0/(32-bits)), each
# opening <ports> UDP flows (ports must be odd so the pg ranges don't alias);
# sessions = subscribers * ports.  Outside pool: /24 (ratio = subs/256).
set -e
W=${1:-1}; BITS=${2:-14}; PORTS=${3:-255}
VPP=${VPP:-$HOME/vpp}/build-root/install-vpp-native/vpp
SUBS=$((1 << BITS)); N=$((SUBS * PORTS))
RUN=/run/vpp-bench; mkdir -p $RUN; rm -f $RUN/cli.sock
CORES="main-core 1"; [ "$W" -gt 0 ] && CORES="$CORES corelist-workers 2-$((W + 1))"
LAST=$(printf '100.64.%d.%d' $(( (SUBS - 1) >> 8 )) $(( (SUBS - 1) & 255 )))
cat > $RUN/startup.conf <<EOC
unix { nodaemon cli-listen $RUN/cli.sock log $RUN/vpp.log }
cpu { $CORES }
memory { main-heap-size 8G }
buffers { buffers-per-numa 256000 }
statseg { size 256M }
plugins { plugin dpdk_plugin.so { disable } }
cgnat { sessions-per-subscriber 1000 timeouts { udp 3600 } }
EOC
cat > $RUN/setup.cli <<EOC
create packet-generator interface pg0
create packet-generator interface pg1
ip table add 1
set interface ip table pg0 1
set interface state pg0 up
set interface state pg1 up
set interface ip address pg0 100.127.255.254/10
set interface ip address pg1 172.31.0.1/24
set ip neighbor pg1 172.31.0.2 02:00:00:00:00:02
ip route add 0.0.0.0/0 via 172.31.0.2 pg1
cgnat map add inside 100.64.0.0/$((32 - BITS)) inside-vrf 1 outside 192.0.2.0/24
set interface cgnat in pg0
set interface cgnat out pg1
EOC
pkill -f "vpp -c $RUN/startup.conf" 2>/dev/null || true; sleep 1
LD_LIBRARY_PATH=$VPP/lib/x86_64-linux-gnu $VPP/bin/vpp -c $RUN/startup.conf > $RUN/stdout 2>&1 &
PID=$!
C() { $VPP/bin/vppctl -s $RUN/cli.sock "$@"; }
for i in $(seq 50); do [ -S $RUN/cli.sock ] && C show version >/dev/null 2>&1 && break; sleep 0.2; done
C exec $RUN/setup.cli
stream() { # name limit
  local worker=""; [ "$W" -gt 0 ] && worker="worker 0"
  C packet-generator new "{ name $1 limit $2 size 64-64 interface pg0 node ip4-input $worker data { UDP: 100.64.0.0 - $LAST -> 8.8.8.8 UDP: 1024 - $((1024 + PORTS - 1)) -> 53 length 128 checksum 0 incrementing 1 } }"
}
sessions() { C show cgnat status | sed -n 's/.*sessions \([0-9]*\).*/\1/p'; }
heap() { C show memory main-heap | awk '/used/ {for(i=1;i<=NF;i++) if ($i=="used:") {print $(i+1); exit}}'; }

echo "== workers=$W subscribers=$SUBS ports/sub=$PORTS sessions=$N"
H0=$(C show memory main-heap | grep -m1 -o 'used: [0-9.]*[KMG]' )
stream new $N
T0=$(date +%s.%N); C packet-generator enable-stream new
while :; do S=$(sessions); [ "$S" -ge "$N" ] && break; sleep 0.1
  [ $(echo "$(date +%s.%N) - $T0 > 600" | bc) = 1 ] && break; done
T1=$(date +%s.%N)
echo "new sessions: $S in $(echo "$T1 - $T0" | bc) s = $(echo "$S / ($T1 - $T0)" | bc) sessions/s (wall, incl. CLI polling)"
H1=$(C show memory main-heap | grep -m1 -o 'used: [0-9.]*[KMG]')
echo "main heap: before $H0, after $H1"
C packet-generator delete new
C show errors | grep -i cgnat || true

# established flows: replay the same flows for 10 s
stream est $((N * 1000))
C clear runtime; C packet-generator enable-stream est; sleep 10
C show runtime > $RUN/runtime.txt; C packet-generator disable-stream est
echo "--- established flows (10 s): per node (thread, vectors/s, clocks/packet)"
awk '/^Thread/ {t=$2} $1 ~ /^(cgnat-in2out|ip4-input|ip4-lookup|ip4-rewrite|pg-input)$/ {printf "  thread %-2s %-14s %12d pkts %10.0f pps  %7.1f clocks/pkt  %6.1f pkts/call\n", t, $1, $4, $4/10, $6, $7}' $RUN/runtime.txt
grep -E "vector rates|Time" $RUN/runtime.txt | head -8
C show errors | grep -i -E "cgnat|drop" || true
kill $PID; wait $PID 2>/dev/null || true
