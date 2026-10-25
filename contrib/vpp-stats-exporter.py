#!/usr/bin/env python3
"""Prometheus exporter for a VPP node running the cgnat plugin.

Reads VPP's stats segment directly (vpp_papi.vpp_stats, read-only, no
barrier) on every scrape, and names interfaces as the CLI does (after
`set interface name`).  Serves /metrics on :9483 by default.

    vpp-stats-exporter.py [--port 9483] [--socket /run/vpp/stats.sock]

Metrics (all labelled by the scraping job with the node):
  vpp_up                                   1 while the stats segment is readable
  vpp_interface_{rx,tx}_{packets,bytes}_total{interface}
  vpp_interface_{rx_miss,rx_no_buf,rx_error,tx_error,drops}_total{interface}
  vpp_interface_link_up{interface}         1/0 (from the CLI, cached 30 s)
  vpp_cgnat_{in2out,out2in,hairpin}_packets_total{thread}
  vpp_cgnat_steered_{in,out}_total{thread}
  vpp_cgnat_sync_{records_in,records_out,retransmits,overflow}_total{thread}
  vpp_cgnat_{sessions,mappings,subscribers}{thread}
  vpp_cgnat_cluster_{ready,peer_alive,fenced}
  vpp_errors_total{node,reason}            cgnat-*, bond, bfd, ip4 drop paths
  vpp_vector_rate{thread}, vpp_buffers{pool,state}
"""
import argparse
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vpp_papi.vpp_stats import VPPStats

ERR_NODES = re.compile(r"^/err/(cgnat-[^/]+|bond-input|bfd-udp4-input|ip4-input|"
                       r"ip4-local|ip4-glean|ip4-arp|ip4-drop|null-node)/(.+)$")
CGNAT_COUNTERS = {
    "/cgnat/in2out-packets": "vpp_cgnat_in2out_packets_total",
    "/cgnat/out2in-packets": "vpp_cgnat_out2in_packets_total",
    "/cgnat/hairpin-packets": "vpp_cgnat_hairpin_packets_total",
    "/cgnat/steered-in": "vpp_cgnat_steered_in_total",
    "/cgnat/steered-out": "vpp_cgnat_steered_out_total",
    "/cgnat/sync/records-in": "vpp_cgnat_sync_records_in_total",
    "/cgnat/sync/records-out": "vpp_cgnat_sync_records_out_total",
    "/cgnat/sync/retransmits": "vpp_cgnat_sync_retransmits_total",
    "/cgnat/sync/overflow": "vpp_cgnat_sync_overflow_total",
}
CGNAT_GAUGES = {
    "/cgnat/sessions": "vpp_cgnat_sessions",
    "/cgnat/mappings": "vpp_cgnat_mappings",
    "/cgnat/subscribers": "vpp_cgnat_subscribers",
}
CLUSTER = {
    "/cgnat/cluster/ready": "vpp_cgnat_cluster_ready",
    "/cgnat/cluster/peer-alive": "vpp_cgnat_cluster_peer_alive",
    "/cgnat/cluster/fenced": "vpp_cgnat_cluster_fenced",
}
IF_COMBINED = {"/if/rx": "rx", "/if/tx": "tx"}
IF_SIMPLE = {"/if/rx-miss": "rx_miss", "/if/rx-no-buf": "rx_no_buf",
             "/if/rx-error": "rx_error", "/if/tx-error": "tx_error",
             "/if/drops": "drops"}


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class CliCache:
    """Interface display names and link state from the CLI, cached."""

    def __init__(self, ttl=30.0):
        self.ttl, self.at, self.names, self.link = ttl, 0.0, {}, {}
        self.lock = threading.Lock()

    def refresh(self):
        with self.lock:
            if time.time() - self.at < self.ttl:
                return
            names, link = {}, {}
            try:
                out = subprocess.run(["vppctl", "show", "hardware-interfaces", "brief"],
                                     capture_output=True, text=True, timeout=5).stdout
                for line in out.splitlines():
                    m = re.match(r"^(\S+)\s+(\d+)\s+(up|down)\s+(\S+)", line)
                    if m:
                        names[int(m.group(2))] = m.group(1)
                        link[m.group(1)] = 1 if m.group(3) == "up" else 0
            except Exception:
                pass
            if names:
                self.names, self.link = names, link
            self.at = time.time()


class Exporter:
    def __init__(self, sock):
        self.sock = sock
        self.stats = None
        self.cli = CliCache()

    def connect(self):
        if self.stats is None:
            s = VPPStats(self.sock)
            s.connect()
            self.stats = s
        return self.stats

    def collect(self):
        out = []
        try:
            s = self.connect()
            self.cli.refresh()
            stat_names = s["/if/names"]
        except Exception:
            self.stats = None
            return "# vpp stats segment unavailable\nvpp_up 0\n"

        def ifname(i):
            return self.cli.names.get(i) or (stat_names[i] if i < len(stat_names) else str(i))

        out.append("vpp_up 1")
        for path, d in IF_COMBINED.items():
            v = s[path]
            nif = len(v[0]) if v else 0
            for i in range(nif):
                pk = sum(t[i]["packets"] for t in v)
                by = sum(t[i]["bytes"] for t in v)
                n = esc(ifname(i))
                out.append(f'vpp_interface_{d}_packets_total{{interface="{n}"}} {pk}')
                out.append(f'vpp_interface_{d}_bytes_total{{interface="{n}"}} {by}')
        for path, d in IF_SIMPLE.items():
            v = s[path]
            nif = len(v[0]) if v else 0
            for i in range(nif):
                out.append(f'vpp_interface_{d}_total{{interface="{esc(ifname(i))}"}} '
                           f'{sum(t[i] for t in v)}')
        for name, up in self.cli.link.items():
            out.append(f'vpp_interface_link_up{{interface="{esc(name)}"}} {up}')

        for path, metric in list(CGNAT_COUNTERS.items()) + list(CGNAT_GAUGES.items()):
            try:
                v = s[path]
            except Exception:
                continue
            for th, row in enumerate(v):
                out.append(f'{metric}{{thread="{th}"}} {row[0] if row else 0}')
        for path, metric in CLUSTER.items():
            try:
                out.append(f"{metric} {int(s[path])}")
            except Exception:
                pass

        for key in s.ls(["/err/"]):
            m = ERR_NODES.match(key)
            if not m:
                continue
            try:
                v = s[key]
                total = sum(v) if isinstance(v, list) else v
            except Exception:
                continue
            out.append(f'vpp_errors_total{{node="{esc(m.group(1))}",reason="{esc(m.group(2))}"}} {total}')

        try:
            for th, r in enumerate(s["/sys/vector_rate_per_worker"][0]):
                out.append(f'vpp_vector_rate{{thread="{th}"}} {r}')
        except Exception:
            pass
        for key in s.ls(["/buffer-pools/"]):
            parts = key.split("/")
            if len(parts) == 4:
                out.append(f'vpp_buffers{{pool="{esc(parts[2])}",state="{esc(parts[3])}"}} '
                           f'{int(s[key])}')
        return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9483)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--socket", default="/run/vpp/stats.sock")
    a = ap.parse_args()
    exp = Exporter(a.socket)
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0] != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            with lock:
                body = exp.collect().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer((a.bind, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
