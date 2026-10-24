#!/usr/bin/env python3
"""UDP probe flows.  server: echo, appending the source ip:port it saw.
client: N flows at R pps for T seconds; report per flow the public
endpoints seen, loss and the longest gap."""
import json, socket, sys, threading, time

SRC_BASE = "100.64.0.%d"  # flow i binds to 100.64.0.(12+i): one subscriber each

def server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data + b"|%s:%d" % (addr[0].encode(), addr[1]), addr)

def client(dst, port, n, pps, secs, out):
    socks = []
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((SRC_BASE % (12 + i), 40000 + i)); s.settimeout(0.001); socks.append(s)
    stats = [dict(sent=0, recv=0, endpoints={}, last_rx=None, max_gap=0.0) for _ in range(n)]
    end = time.time() + secs; seq = 0; interval = 1.0 / pps
    nxt = time.time()
    while time.time() < end:
        now = time.time()
        if now >= nxt:
            for i, s in enumerate(socks):
                s.sendto(b"%d %d %.6f" % (i, seq, now), (dst, port)); stats[i]["sent"] += 1
            seq += 1; nxt += interval
        for i, s in enumerate(socks):
            try:
                data, _ = s.recvfrom(2048)
            except (socket.timeout, BlockingIOError):
                continue
            st = stats[i]; t = time.time()
            ep = data.rsplit(b"|", 1)[1].decode()
            st["endpoints"][ep] = st["endpoints"].get(ep, 0) + 1
            st["recv"] += 1
            if st["last_rx"] is not None:
                st["max_gap"] = max(st["max_gap"], t - st["last_rx"])
            st["last_rx"] = t
    for st in stats:
        st.pop("last_rx")
    json.dump(stats, open(out, "w"), indent=1)

if sys.argv[1] == "server":
    server(int(sys.argv[2]))
else:
    client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]),
           float(sys.argv[6]), sys.argv[7])
