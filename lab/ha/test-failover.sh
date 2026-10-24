#!/bin/bash
# Kill/restore test.  Assumes up.sh has run.  Prints PASS/FAIL lines.
#   test-failover.sh [duration=60] [kill_at=15] [restore_at=35]
cd "$(dirname "$0")"; . ./common.sh
D=${1:-60}; K=${2:-15}; R=${3:-35}
OUT=$RUN/results; rm -rf $OUT; mkdir -p $OUT
pkill -f watch.sh; ./watch.sh $OUT/watch.log & WPID=$!
NS srv iperf3 -s -D -p 5201 --logfile $OUT/iperf-server.log
NS srv iperf3 -s -D -p 5202 --logfile $OUT/iperf-server2.log
NS srv python3 udpflows.py server 7000 & SPID=$!
sleep 1
NS cli timeout $((D + 15)) iperf3 -c 198.51.100.10 -p 5201 -P 8 -t $D -b 20M -i 1 --connect-timeout 3000 --json > $OUT/iperf.json 2>&1 &
IPID=$!
NS cli timeout $((D + 15)) iperf3 -c 198.51.100.10 -B 100.64.0.11 -p 5202 -P 4 -t $D -b 20M -i 1 --connect-timeout 3000 --json > $OUT/iperf2.json 2>&1 &
IPID2=$!
NS cli python3 udpflows.py client 198.51.100.10 7000 16 10 $D $OUT/udp.json &
UPID=$!
sleep 3
NS srv ss -tnH state established "( sport = :5201 or sport = :5202 )" | awk '{print $4}' | sort > $OUT/tcp-before.txt
vppctl_a show cgnat status > $OUT/a-before.txt; vppctl_b show cgnat status > $OUT/b-before.txt
vppctl_a show cgnat lookup forward 100.64.0.10 > $OUT/forward-before.txt
# dual sessions: both nodes' tables, a moment apart, while traffic flows
vppctl_a show cgnat sessions > $OUT/a-sessions.txt; vppctl_b show cgnat sessions > $OUT/b-sessions.txt
sleep $((K - 4))
echo "$(date +%T) kill -9 B"; kill -9 $(cat $RUN/b.pid); KT=$(date +%s.%N)
sleep 2; vppctl_a show cgnat cluster > $OUT/a-after-kill.txt
sleep $((R - K - 2))
echo "$(date +%T) restart B"
setsid $VPPDIR/bin/vpp -c $RUN/b.conf > $RUN/b.stdout 2>&1 < /dev/null & echo $! > $RUN/b.pid
sleep $((D - R - 8))
vppctl_a show cgnat cluster > $OUT/a-end.txt; vppctl_b show cgnat cluster > $OUT/b-end.txt
vppctl_a show cgnat status > $OUT/a-end-status.txt; vppctl_b show cgnat status > $OUT/b-end-status.txt
NS srv ss -tnH state established "( sport = :5201 or sport = :5202 )" | awk '{print $4}' | sort > $OUT/tcp-after.txt
vppctl_a show cgnat lookup forward 100.64.0.10 > $OUT/forward-after.txt
wait $IPID $IPID2 $UPID
kill $WPID $SPID 2>/dev/null; pkill -f "iperf3 -s"
python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]; ok = True
def res(name, cond, detail=""):
    global ok
    ok &= bool(cond); print(("PASS" if cond else "FAIL"), name, detail)
for name, n in (("iperf.json", 8), ("iperf2.json", 4)):
    try:
        ip = json.load(open(out + "/" + name))
        err = ip.get("error")
        streams = ip["end"]["streams"] if "end" in ip else []
        res("%s completed without error, %d streams" % (name, n), not err and len(streams) == n, err or "")
        ints = ip.get("intervals", [])
        zero = [i for i, iv in enumerate(ints) if iv["sum"]["bits_per_second"] < 1e5]
        res("%s throughput never zero for more than 2 s" % name, len(zero) <= 2, "zero intervals at %s" % zero)
        print("  %s Mbit/s per second:" % name, " ".join("%.0f" % (iv["sum"]["bits_per_second"] / 1e6) for iv in ints))
    except Exception as e:
        res(name, False, repr(e))
before = open(out + "/tcp-before.txt").read().split(); after = open(out + "/tcp-after.txt").read().split()
res("same 14 tcp connections (public ip:port) before and after", before == after and len(before) == 14,
    "before %d after %d" % (len(before), len(after)))
u = json.load(open(out + "/udp.json"))
eps = [list(f["endpoints"]) for f in u]
res("every udp flow kept one public ip:port", all(len(e) == 1 for e in eps), str([e for e in eps if len(e) != 1]))
loss = [f["sent"] - f["recv"] for f in u]; gaps = [round(f["max_gap"], 2) for f in u]
res("udp loss per flow <= 40 packets (2 s x 2 events at 10 pps)", max(loss) <= 40, "loss %s" % loss)
print("  udp max gap per flow (s):", gaps)
def sessions(f):
    out = {}
    for l in open(f):
        w = l.split()
        if len(w) > 12 and w[0] == "thread":
            # thread N proto in:port fib F -> out:port <-> remote:port class idle Ns owned|warm
            out[(w[2], w[3], w[7], w[9])] = w[-1]
    return out
sa, sb = sessions(out + "/a-sessions.txt"), sessions(out + "/b-sessions.txt")
common = set(sa) & set(sb)
only = (set(sa) ^ set(sb))
one_owner = all(sorted((sa[k], sb[k])) == ["owned", "warm"] for k in common)
res("dual sessions: both nodes hold the same sessions (%d on A, %d on B, %d differ while flows churn)"
    % (len(sa), len(sb), len(only)), len(common) >= 20 and len(only) <= max(2, len(common) // 20))
res("dual sessions: every shared session is owned on exactly one node and warm on the other", one_owner,
    str([(k, sa[k], sb[k]) for k in common if sorted((sa[k], sb[k])) != ["owned", "warm"]][:3]))
res("dual sessions: both nodes own some (load shared)",
    any(v == "owned" for v in sa.values()) and any(v == "owned" for v in sb.values()))
res("mapping unchanged", open(out + "/forward-before.txt").read() == open(out + "/forward-after.txt").read())
def steered(f):
    for l in open(f):
        if "steered-out" in l:
            return int(l.split("steered-out")[1].split()[0].strip(","))
    return 0
res("traffic crossed the pair link (steered-out > 0 on both before the kill)",
    steered(out + "/a-before.txt") > 0 and steered(out + "/b-before.txt") > 0)
res("both nodes ready at the end", ": ready," in open(out + "/a-end.txt").readline()
    and ": ready," in open(out + "/b-end.txt").readline())
print("RESULT", "PASS" if ok else "FAIL")
PY
