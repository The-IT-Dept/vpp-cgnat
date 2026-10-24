#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vpp-cgnat HA pair tests: VPP is node 1, scapy plays the peer (node 2)."""

import ipaddress
import os
import struct
import time
import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from framework import VppTestCase
from asfframework import VppTestRunner

PORT = 6200
HELLO, STEER, SYNC, ACK, RESYNC_REQ, RESYNC_END = 1, 2, 3, 4, 5, 6
HDR = struct.Struct("!BBBBIII")  # version type flags node_id config_hash epoch seq
HELLO_BODY = struct.Struct("!BBHHH")  # path_id state n_workers first_worker pad
STEER_BODY = struct.Struct("!BBBBIHH")  # direction reass_flags flags_or_type pad table_id sport dport
REASS_NON_FIRST, REASS_TRUNCATED = 1, 2
SYNC_BODY = struct.Struct("!HHHH")  # src_thread dst_thread n_records pad
ACK_BODY = struct.Struct("!HHI")  # src_thread dst_thread pad
END_BODY = struct.Struct("!HH")  # src_thread n_src_threads
RECORD = struct.Struct("!BBBBIIIHHIHHI")  # 32 bytes
READY, FENCED, WANT_RESYNC = 1, 2, 4


def ip2int(a):
    return int(ipaddress.ip_address(a))


def int2ip(i):
    return str(ipaddress.ip_address(i))


def parse(payload):
    """Parse a cluster message: (header dict, body bytes)."""
    v, t, flags, node, chash, epoch, seq = HDR.unpack_from(payload)
    return (
        dict(version=v, type=t, flags=flags, node_id=node, config_hash=chash,
             epoch=epoch, seq=seq),
        payload[HDR.size:],
    )


def parse_records(body):
    src, dst, n, _ = SYNC_BODY.unpack_from(body)
    recs = []
    for i in range(n):
        f = RECORD.unpack_from(body, SYNC_BODY.size + i * RECORD.size)
        recs.append(dict(op=f[0], proto=f[1], tcp_state=f[2], to_class=f[3],
                         in_table_id=f[4], in_addr=int2ip(f[5]), out_addr=int2ip(f[6]),
                         in_port=f[7], out_port=f[8], remote_addr=int2ip(f[9]),
                         remote_port=f[10], idle_ds=f[11]))
    return src, dst, recs


def record(op, in_addr, in_port, out_addr, out_port, remote_addr, remote_port,
           proto=0, tcp_state=0, to_class=2, in_table_id=0, idle_ds=0):
    return RECORD.pack(op, proto, tcp_state, to_class, in_table_id, ip2int(in_addr),
                       ip2int(out_addr), in_port, out_port, ip2int(remote_addr),
                       remote_port, idle_ds, 0)


class CgnatClusterCase(VppTestCase):
    """VPP node 1: pg0 inside, pg1 outside, pg2 pair link, pg3 probe path.

    Map 172.16.1.0/24 -> 192.0.2.0/28.  The peer (scapy) is node 2 at
    pg2.remote_ip4 (pair) and pg3.remote_ip4 (probe).
    """

    node_id = 1
    peer_id = 2
    n_inside_hosts = 32

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(4))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.pg0.generate_remote_hosts(cls.n_inside_hosts + 1)
        cls.pg0.configure_ipv4_neighbors()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.epoch = 0x1234
        self.vapi.cgnat_map_add_del(is_add=1, in_vrf=0, in_addr=self.inside_net(),
                                    in_plen=24, out_vrf=0, out_addr="192.0.2.0",
                                    out_plen=28)
        for sw, inside in ((self.pg0, 1), (self.pg1, 0)):
            self.vapi.cgnat_interface_add_del_feature(is_add=1, is_inside=inside,
                                                      sw_if_index=sw.sw_if_index)
        self.cluster_on()

    def tearDown(self):
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show cgnat cluster"))
            self.vapi.cgnat_cluster_set(enable=0)
            for sw, inside in ((self.pg0, 1), (self.pg1, 0)):
                self.vapi.cgnat_interface_add_del_feature(
                    is_add=0, is_inside=inside, sw_if_index=sw.sw_if_index)
            for m in self.vapi.cgnat_map_dump():
                self.vapi.cgnat_map_add_del(is_add=0, in_vrf=m.in_vrf, in_addr=m.in_addr,
                                            in_plen=m.in_plen, out_vrf=m.out_vrf,
                                            out_addr=m.out_addr, out_plen=m.out_plen)
        super().tearDown()

    # --- helpers

    def cluster_on(self, **kw):
        args = dict(enable=1, node_id=self.node_id, local=self.pg2.local_ip4,
                    peer=self.pg2.remote_ip4, table_id=0, port=PORT,
                    hello_interval_ms=100, dead_interval_ms=500, refresh_interval_s=10)
        args.update(kw)
        self.vapi.cgnat_cluster_set(**args)

    def inside_net(self):
        return str(ipaddress.ip_network(self.pg0.local_ip4 + "/24", strict=False)
                   .network_address)

    def host(self, i=0):
        return self.pg0.remote_hosts[i + 1].ip4

    def status(self):
        return self.vapi.cgnat_cluster_get_status()

    def wait_for(self, cond, timeout=3.0, step=0.05):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            self.sleep(step)
        return cond()

    def err(self, node, name):
        return self.statistics.get_err_counter("/err/%s/%s" % (node, name))

    def msg(self, mtype, body=b"", seq=0, node_id=None, config_hash=None, epoch=None,
            path=0):
        st = self.status()
        hdr = HDR.pack(1, mtype, 0, self.peer_id if node_id is None else node_id,
                       st.config_hash if config_hash is None else config_hash,
                       self.epoch if epoch is None else epoch, seq)
        itf = self.pg2 if path == 0 else self.pg3
        return (Ether(src=itf.remote_mac, dst=itf.local_mac)
                / IP(src=itf.remote_ip4, dst=itf.local_ip4)
                / UDP(sport=PORT, dport=PORT) / Raw(hdr + body))

    def hello(self, state=READY, path=0, n_workers=0, first_worker=0, **kw):
        return self.msg(HELLO, HELLO_BODY.pack(path, state, n_workers, first_worker, 0),
                        path=path, **kw)

    def send_peer(self, pkts, itf=None):
        itf = itf or self.pg2
        itf.add_stream(pkts if isinstance(pkts, list) else [pkts])
        self.pg_start()

    def keep_hello(self, seconds, path=0, **kw):
        """Send peer HELLOs every 100 ms for `seconds`."""
        end = time.time() + seconds
        while time.time() < end:
            self.send_peer(self.hello(path=path, **kw), self.pg2 if path == 0 else self.pg3)
            self.sleep(0.1)

    def assert_not_translated(self, pkts, itf_in=None, remark=""):
        """Send on itf_in (default pg0): nothing reaches the other side and no
        steer goes to the peer (our own HELLOs on pg2/pg3 are expected)."""
        itf_in = itf_in or self.pg0
        out = self.pg1 if itf_in == self.pg0 else self.pg0
        out.enable_capture()
        self.pg2.enable_capture()
        itf_in.add_stream(pkts)
        self.pg_start()
        self.sleep(0.1)
        out.assert_nothing_captured(remark=remark)
        self.assertEqual(self.capture_msgs(self.pg2, STEER), [], remark)

    def capture_msgs(self, itf, mtype):
        """Stop capturing on itf; cluster messages of a type it captured."""
        itf.disable_capture()
        out = []
        if not os.path.isfile(itf.out_path):
            return out
        for p in rdpcap(itf.out_path):
            if UDP in p and p[UDP].dport == PORT:
                h, body = parse(bytes(p[UDP].payload))
                if h["type"] == mtype:
                    out.append((p, h, body))
        return out


class TestCgnatClusterHello(CgnatClusterCase):
    """Cluster: HELLOs, liveness, config hash, starting/alone"""

    def test_hello_sent(self):
        """HELLOs go out on the pair link with version, node id, hash and epoch"""
        self.pg2.enable_capture()
        self.sleep(0.5)
        hellos = self.capture_msgs(self.pg2, HELLO)
        self.assertGreaterEqual(len(hellos), 3)
        p, h, body = hellos[-1]
        st = self.status()
        self.assertEqual((h["version"], h["node_id"]), (1, 1))
        self.assertEqual(h["config_hash"], st.config_hash)
        self.assertNotEqual(h["epoch"], 0)
        self.assertEqual((p[IP].src, p[IP].dst), (self.pg2.local_ip4, self.pg2.remote_ip4))
        self.assertEqual(HELLO_BODY.unpack_from(body)[0], 0)  # path 0

    def test_starting_then_alone(self):
        """Starting: not ready, traffic dropped; after the dead interval: alone and ready"""
        st = self.status()
        self.assertEqual((st.ready, st.reason), (False, "starting"))
        before = self.err("cgnat-in2out", "not-ready")
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
             / IP(src=self.host(), dst=self.pg1.remote_ip4) / UDP(sport=5000, dport=53))
        self.assert_not_translated([p], remark="starting")
        self.assertEqual(self.err("cgnat-in2out", "not-ready") - before, 1)
        self.assertTrue(self.wait_for(lambda: self.status().ready))
        self.assertEqual(self.status().reason, "alone")
        self.send_and_expect(self.pg0, [p], self.pg1)

    def test_peer_alive_and_dead(self):
        """Peer liveness follows its HELLOs"""
        self.keep_hello(1.0)
        self.assertTrue(self.status().peer_alive)
        self.assertTrue(self.status().pair_alive)
        self.assertTrue(self.wait_for(lambda: not self.status().peer_alive, timeout=2))

    def test_config_hash_tracks_maps(self):
        """Config hash changes with the maps and returns when they do"""
        h0 = self.status().config_hash
        self.vapi.cgnat_map_add_del(is_add=1, in_vrf=0, in_addr="100.64.0.0", in_plen=24,
                                    out_vrf=0, out_addr="198.51.100.0", out_plen=28)
        self.assertTrue(self.wait_for(lambda: self.status().config_hash != h0))
        self.vapi.cgnat_map_add_del(is_add=0, in_vrf=0, in_addr="100.64.0.0", in_plen=24,
                                    out_vrf=0, out_addr="198.51.100.0", out_plen=28)
        self.assertTrue(self.wait_for(lambda: self.status().config_hash == h0))

    def test_config_mismatch(self):
        """A peer with a different config hash: not ready, config-mismatch"""
        self.wait_for(lambda: self.status().ready)
        self.keep_hello(0.6, config_hash=0xDEADBEEF)
        st = self.status()
        self.assertEqual((st.ready, st.reason), (False, "config-mismatch"))

    def test_duplicate_node_id_refused(self):
        """A peer using our node id is never alive; duplicate-node-id"""
        self.keep_hello(0.8, node_id=1)
        st = self.status()
        self.assertFalse(st.peer_alive)
        self.assertEqual((st.ready, st.reason), (False, "duplicate-node-id"))

    def test_probe_path_hello(self):
        """Extra liveness path: HELLOs on it carry its path id"""
        self.vapi.cgnat_cluster_path_add_del(is_add=1, local=self.pg3.local_ip4,
                                             peer=self.pg3.remote_ip4, table_id=0)
        self.pg3.enable_capture()
        self.sleep(0.5)
        hellos = self.capture_msgs(self.pg3, HELLO)
        self.assertGreaterEqual(len(hellos), 2)
        self.assertEqual(HELLO_BODY.unpack_from(hellos[-1][2])[0], 1)
        self.vapi.cgnat_cluster_path_add_del(is_add=0, local=self.pg3.local_ip4,
                                             peer=self.pg3.remote_ip4, table_id=0)


class CgnatOwnerCase(CgnatClusterCase):
    """Long dead interval so ownership can be sampled while the peer is 'alive'."""

    dead_ms = 2000

    def setUp(self):
        super().setUp()
        self.cluster_on(dead_interval_ms=self.dead_ms)
        self.assertTrue(self.wait_for(lambda: self.status().ready, timeout=4))

    def owners(self, n=256):
        net = ipaddress.ip_network(self.inside_net() + "/24")
        counts = {}
        for i in range(n):
            o = self.vapi.cgnat_cluster_owner(in_vrf=0, in_addr=str(net[i])).node_id
            counts[o] = counts.get(o, 0) + 1
        return counts


class TestCgnatClusterOwner(CgnatOwnerCase):
    """Cluster ownership (we are node 1)"""

    def test_owner_alone_is_self(self):
        """Alone: we own every subscriber"""
        self.assertEqual(self.owners(), {1: 256})

    def test_owner_split_with_peer(self):
        """Peer alive and ready: subscribers split between the nodes"""
        self.keep_hello(0.5)
        c = self.owners()
        self.assertEqual(set(c), {1, 2})
        self.assertTrue(96 <= c[1] <= 160, c)

    def test_owner_peer_not_ready(self):
        """Peer alive but not ready: we own everyone"""
        self.keep_hello(0.5, state=0)
        self.assertEqual(self.owners(), {1: 256})

    def test_takeover_when_all_paths_dead(self):
        """Peer silent on every path: we own everyone again, ready"""
        self.keep_hello(0.5)
        self.assertTrue(self.wait_for(lambda: not self.status().peer_alive, timeout=4))
        self.assertEqual(self.owners(), {1: 256})
        self.assertTrue(self.status().ready)

    def test_no_fence_lower_id(self):
        """Pair link down, peer alive on a probe path, we have the lower id: not fenced"""
        self.vapi.cgnat_cluster_path_add_del(is_add=1, local=self.pg3.local_ip4,
                                             peer=self.pg3.remote_ip4, table_id=0)
        self.keep_hello(1.0, path=1)
        st = self.status()
        self.assertTrue(st.peer_alive)
        self.assertFalse(st.pair_alive)
        self.assertEqual((st.fenced, st.ready), (False, True))
        self.assertEqual(self.owners(), {1: 256})

    def test_mismatch_freezes_ownership(self):
        """Config mismatch: not ready, ownership stays as last agreed"""
        self.keep_hello(0.5)
        before = self.owners()
        self.keep_hello(0.5, config_hash=0xDEADBEEF)
        st = self.status()
        self.assertEqual((st.ready, st.reason), (False, "config-mismatch"))
        self.assertEqual(self.owners(), before)


class TestCgnatClusterFence(CgnatOwnerCase):
    """Cluster fencing (we are node 2, the peer is node 1)"""

    node_id = 2
    peer_id = 1

    def test_fence_higher_id(self):
        """Pair link down, peer alive on a probe path, we have the higher id: fenced"""
        self.vapi.cgnat_cluster_path_add_del(is_add=1, local=self.pg3.local_ip4,
                                             peer=self.pg3.remote_ip4, table_id=0)
        self.keep_hello(1.0, path=1)
        st = self.status()
        self.assertEqual((st.fenced, st.ready, st.reason), (True, False, "fenced"))
        self.assertEqual(self.owners(), {1: 256})


class TestCgnatClusterSteer(CgnatOwnerCase):
    """Cluster steering over the pair link (we are node 1)"""

    def peer_hosts(self, owner):
        out = []
        for i in range(self.n_inside_hosts):
            if self.vapi.cgnat_cluster_owner(in_vrf=0, in_addr=self.host(i)).node_id == owner:
                out.append(self.host(i))
        return out

    def split(self):
        self.keep_hello(0.4)
        mine, theirs = self.peer_hosts(1), self.peer_hosts(2)
        self.assertTrue(mine and theirs)
        return mine, theirs

    def udp_in(self, src, sport=5000, payload=b"x" * 16):
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=src, dst=self.pg1.remote_ip4) / UDP(sport=sport, dport=53)
                / Raw(payload))

    def steer(self, direction, inner, table_id=0, reass_flags=0, flags=0):
        ipb = bytes(inner[IP])
        ip = IP(ipb)
        l4 = ip.payload
        sport = getattr(l4, "sport", getattr(l4, "id", 0))
        dport = getattr(l4, "dport", getattr(l4, "id", 0))
        return self.msg(STEER, STEER_BODY.pack(direction, reass_flags, flags, 0, table_id,
                                               sport, dport) + ipb)

    def sent_steers(self, itf_in, pkts):
        self.pg2.enable_capture()
        itf_in.add_stream(pkts)
        self.pg_start()
        self.sleep(0.2)
        return self.capture_msgs(self.pg2, STEER)

    def test_outbound_for_peer_steered(self):
        """Outbound from a peer-owned subscriber goes to the peer, untouched"""
        mine, theirs = self.split()
        p = self.udp_in(theirs[0])
        self.pg1.enable_capture()
        steers = self.sent_steers(self.pg0, [p])
        self.assertEqual(len(steers), 1)
        d, rf, fl, _, table, sport, dport = STEER_BODY.unpack_from(steers[0][2])
        self.assertEqual((d, table, sport, dport), (0, 0, 5000, 53))
        self.assertEqual(steers[0][2][STEER_BODY.size:], bytes(p[IP]))
        self.pg1.assert_nothing_captured(remark="not translated here")

    def test_inbound_for_peer_steered(self):
        """Inbound to a peer-owned subscriber's block goes to the peer"""
        mine, theirs = self.split()
        f = self.vapi.cgnat_forward(in_vrf=0, in_addr=theirs[0])
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
             / IP(src=self.pg1.remote_ip4, dst=str(f.out_addr))
             / UDP(sport=53, dport=f.port_lo + 7) / Raw(b"y" * 16))
        steers = self.sent_steers(self.pg1, [p])
        self.assertEqual(len(steers), 1)
        d, rf, fl, _, table, sport, dport = STEER_BODY.unpack_from(steers[0][2])
        self.assertEqual((d, sport, dport), (1, 53, f.port_lo + 7))

    def test_steered_in_translated(self):
        """A steered outbound packet for our subscriber is translated here"""
        mine, theirs = self.split()
        p = self.udp_in(mine[0], sport=5100)
        rx = self.send_and_expect(self.pg2, [self.steer(0, p)], self.pg1)[0]
        f = self.vapi.cgnat_forward(in_vrf=0, in_addr=mine[0])
        self.assertEqual(rx[IP].src, str(f.out_addr))
        self.assertEqual(rx[UDP].sport, f.port_lo + 5100 % (f.port_hi - f.port_lo + 1))

    def test_steered_out_translated(self):
        """A steered inbound reply for our subscriber is translated here"""
        mine, theirs = self.split()
        rx = self.send_and_expect(self.pg0, [self.udp_in(mine[0], sport=5200)], self.pg1)[0]
        reply = (Ether() / IP(src=self.pg1.remote_ip4, dst=rx[IP].src)
                 / UDP(sport=53, dport=rx[UDP].sport) / Raw(b"r" * 16))
        back = self.send_and_expect(self.pg2, [self.steer(1, reply)], self.pg0)[0]
        self.assertEqual((back[IP].dst, back[UDP].dport), (mine[0], 5200))

    def test_steer_loop_dropped(self):
        """A steered packet for a subscriber we don't own is dropped, never bounced"""
        mine, theirs = self.split()
        before = self.err("cgnat-in2out-steered", "steer-loop")
        self.pg2.enable_capture()
        self.send_peer(self.steer(0, self.udp_in(theirs[0])))
        self.sleep(0.1)
        self.assertEqual(self.capture_msgs(self.pg2, STEER), [])
        self.assertEqual(self.err("cgnat-in2out-steered", "steer-loop") - before, 1)

    def test_steer_large_packet_fragments_and_reassembles(self):
        """Full-size packets steer as outer fragments and reassemble at the owner"""
        mine, theirs = self.split()
        self.vapi.sw_interface_set_mtu(self.pg2.sw_if_index, [1500, 0, 0, 0])
        big = self.udp_in(theirs[0], sport=5300, payload=b"z" * 1472)
        self.pg2.enable_capture()
        self.pg0.add_stream([big])
        self.pg_start()
        self.sleep(0.2)
        self.pg2.disable_capture()
        frags = [p for p in rdpcap(self.pg2.out_path)
                 if IP in p and p[IP].proto == 17 and (p[IP].flags.MF or p[IP].frag)]
        self.assertGreaterEqual(len(frags), 2)
        # and the reverse: the peer's fragmented steer of our subscriber
        steer = self.steer(0, self.udp_in(mine[0], sport=5301, payload=b"q" * 1472))
        pieces = fragment(steer, fragsize=1000)
        rx = self.send_and_expect(self.pg2, pieces, self.pg1, n_rx=1)
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0][UDP].len, 1480)  # (port 53: scapy decodes DNS)
        self.vapi.sw_interface_set_mtu(self.pg2.sw_if_index, [9000, 0, 0, 0])


class TestCgnatClusterSteerWorkers(TestCgnatClusterSteer):
    """Cluster steering with 2 workers"""

    vpp_worker_count = 2


class TestCgnatClusterSteerFenced(CgnatOwnerCase):
    """Fenced node drops subscriber traffic (we are node 2)"""

    node_id = 2
    peer_id = 1

    def test_fenced_drops(self):
        """Fenced: the peer owns everyone but the pair link is down, so drop"""
        self.vapi.cgnat_cluster_path_add_del(is_add=1, local=self.pg3.local_ip4,
                                             peer=self.pg3.remote_ip4, table_id=0)
        self.keep_hello(1.0, path=1)
        self.assertTrue(self.status().fenced)
        before = self.err("cgnat-in2out", "fenced")
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
             / IP(src=self.host(0), dst=self.pg1.remote_ip4) / UDP(sport=5000, dport=53))
        self.assert_not_translated([p], remark="fenced")
        self.assertEqual(self.err("cgnat-in2out", "fenced") - before, 1)


class TestCgnatClusterStartup(VppTestCase):
    """Cluster from startup.conf"""

    extra_vpp_config = [
        "cgnat { cluster { node-id 7 local 10.255.0.1 peer 10.255.0.2 port 6201",
        "hello-interval 200 dead-interval 1000 path local 10.1.0.2 peer 10.1.0.3 } }",
    ]

    def test_startup_cluster(self):
        """startup.conf cluster section enables the pair with its settings"""
        st = self.vapi.cgnat_cluster_get_status()
        self.assertTrue(st.enabled)
        self.assertEqual(st.node_id, 7)
        out = self.vapi.cli("show cgnat cluster")
        self.assertIn("path 1 10.1.0.2 -> 10.1.0.3", out)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
