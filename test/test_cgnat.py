#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vpp-cgnat plugin tests (run with VPP make test, see scripts/test.sh)."""

import ipaddress
import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror, fragment
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework import VppTestCase
from asfframework import VppTestRunner
from util import reassemble4


class TestCgnatPlugin(VppTestCase):
    """CGNAT plugin loads"""

    def test_plugin_loaded(self):
        """cgnat_plugin.so is loaded"""
        out = self.vapi.cli("show plugins")
        self.assertIn("cgnat_plugin.so", out)


def clear_cgnat(test):
    """Delete every cgnat map (flushes sessions)."""
    for m in test.vapi.cgnat_map_dump():
        test.vapi.cgnat_map_add_del(
            is_add=0,
            in_vrf=m.in_vrf,
            in_addr=m.in_addr,
            in_plen=m.in_plen,
            out_vrf=m.out_vrf,
            out_addr=m.out_addr,
            out_plen=m.out_plen,
        )


class TestCgnatMap(VppTestCase):
    """CGNAT maps: det44 formula, forward/reverse lookup"""

    def tearDown(self):
        if not self.vpp_dead:
            clear_cgnat(self)
        super().tearDown()

    def add(self, in_addr, in_plen, out_addr, out_plen, in_vrf=0, out_vrf=0, is_add=1):
        return self.vapi.cgnat_map_add_del(
            is_add=is_add,
            in_vrf=in_vrf,
            in_addr=in_addr,
            in_plen=in_plen,
            out_vrf=out_vrf,
            out_addr=out_addr,
            out_plen=out_plen,
        )

    def fwd(self, in_addr, in_vrf=0):
        return self.vapi.cgnat_forward(in_vrf=in_vrf, in_addr=in_addr)

    def rev(self, out_addr, out_port, out_vrf=0):
        return self.vapi.cgnat_reverse(out_vrf=out_vrf, out_addr=out_addr, out_port=out_port)

    def test_forward_matches_det44(self):
        """Forward lookup matches det44: 100.64.0.0/23 -> 157.20.113.160/28"""
        self.add("100.64.0.0", 23, "157.20.113.160", 28)
        r = self.fwd("100.64.0.5")
        self.assertEqual(r.retval, 0)
        self.assertEqual(
            (str(r.out_addr), r.port_lo, r.port_hi), ("157.20.113.160", 11104, 13119)
        )
        r = self.fwd("100.64.1.255")  # offset 511
        self.assertEqual(
            (str(r.out_addr), r.port_lo, r.port_hi),
            ("157.20.113.175", 1024 + 2016 * 31, 1024 + 2016 * 32 - 1),
        )
        out = self.vapi.cli("show cgnat lookup forward 100.64.0.5")
        self.assertIn("157.20.113.160", out)
        self.assertIn("11104-13119", out)

    def test_reverse_inverts_forward(self):
        """Reverse lookup inverts forward for every subscriber and both block ends"""
        self.add("100.64.0.0", 23, "157.20.113.160", 28)
        base = ipaddress.ip_address("100.64.0.0")
        for off in range(512):
            a = str(base + off)
            f = self.fwd(a)
            for port in (f.port_lo, f.port_hi):
                r = self.rev(str(f.out_addr), port)
                self.assertEqual(r.retval, 0)
                self.assertEqual((str(r.in_addr), r.in_vrf), (a, 0))
        with self.vapi.assert_negative_api_retval():
            self.rev("157.20.113.160", 1023)
        out = self.vapi.cli("show cgnat lookup reverse 157.20.113.160:11104")
        self.assertIn("100.64.0.5", out)

    def test_overlapping_vrfs(self):
        """Same inside prefix in two VRFs maps to different pools"""
        self.add("100.64.0.0", 23, "157.20.113.160", 28, in_vrf=1)
        self.add("100.64.0.0", 23, "157.20.113.176", 28, in_vrf=2)
        self.assertEqual(str(self.fwd("100.64.0.5", in_vrf=1).out_addr), "157.20.113.160")
        self.assertEqual(str(self.fwd("100.64.0.5", in_vrf=2).out_addr), "157.20.113.176")
        r = self.rev("157.20.113.176", 11104)
        self.assertEqual((str(r.in_addr), r.in_vrf), ("100.64.0.5", 2))
        r = self.rev("157.20.113.160", 11104)
        self.assertEqual((str(r.in_addr), r.in_vrf), ("100.64.0.5", 1))

    def test_reject_overlap_same_vrf(self):
        """Overlapping inside prefixes in one VRF are refused"""
        self.add("100.64.0.0", 23, "157.20.113.160", 28)
        with self.vapi.assert_negative_api_retval():
            self.add("100.64.1.0", 24, "157.20.113.176", 28)
        # and overlapping outside pools are refused too
        with self.vapi.assert_negative_api_retval():
            self.add("100.65.0.0", 23, "157.20.113.168", 29)

    def test_reject_bad_ratio(self):
        """Outside bigger than inside (ratio < 1) is refused"""
        with self.vapi.assert_negative_api_retval():
            self.add("100.64.0.0", 28, "157.20.113.0", 23)

    def test_del_removes(self):
        """Deleted map no longer answers lookups"""
        self.add("100.64.0.0", 23, "157.20.113.160", 28)
        self.assertEqual(len(self.vapi.cgnat_map_dump()), 1)
        self.add("100.64.0.0", 23, "157.20.113.160", 28, is_add=0)
        self.assertEqual(len(self.vapi.cgnat_map_dump()), 0)
        with self.vapi.assert_negative_api_retval():
            self.fwd("100.64.0.5")


class CgnatPgCase(VppTestCase):
    """Shared topology: pg0 inside (VRF 1), pg1 outside (VRF 0).

    Map: pg0's subnet 172.16.1.0/24 (inside VRF 1) -> 192.0.2.0/30 (VRF 0),
    ratio 64, 1008 ports per subscriber.
    """

    in_vrf = 1
    pool = "192.0.2.0"
    pool_plen = 30
    n_inside_hosts = 4

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        # class-lifetime table: kept out of the per-test object registry
        cls.vapi.ip_table_add_del_v2(is_add=1, table={"table_id": cls.in_vrf})
        cls.pg0.set_table_ip4(cls.in_vrf)
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.pg0.generate_remote_hosts(cls.n_inside_hosts + 1)
        cls.pg0.configure_ipv4_neighbors()
        cls.pg1.generate_remote_hosts(3)
        cls.pg1.configure_ipv4_neighbors()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        cls.vapi.ip_table_add_del_v2(is_add=0, table={"table_id": cls.in_vrf})
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.vapi.cgnat_map_add_del(
            is_add=1,
            in_vrf=self.in_vrf,
            in_addr=self.inside_net(),
            in_plen=24,
            out_vrf=0,
            out_addr=self.pool,
            out_plen=self.pool_plen,
        )
        self.vapi.cgnat_interface_add_del_feature(
            is_add=1, is_inside=1, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.cgnat_interface_add_del_feature(
            is_add=1, is_inside=0, sw_if_index=self.pg1.sw_if_index
        )

    def tearDown(self):
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show cgnat sessions"))
            self.vapi.cgnat_interface_add_del_feature(
                is_add=0, is_inside=1, sw_if_index=self.pg0.sw_if_index
            )
            self.vapi.cgnat_interface_add_del_feature(
                is_add=0, is_inside=0, sw_if_index=self.pg1.sw_if_index
            )
            clear_cgnat(self)
        super().tearDown()

    # helpers

    def inside_net(self):
        return str(ipaddress.ip_network(self.pg0.local_ip4 + "/24", strict=False).network_address)

    def host(self, i=0):
        """i-th inside subscriber address (remote hosts start at .2)"""
        return self.pg0.remote_hosts[i + 1].ip4

    def block(self, in_addr):
        f = self.vapi.cgnat_forward(in_vrf=self.in_vrf, in_addr=in_addr)
        return str(f.out_addr), f.port_lo, f.port_hi

    def first_choice(self, in_addr, in_port):
        out, lo, hi = self.block(in_addr)
        return out, lo + in_port % (hi - lo + 1)

    def err(self, node, name):
        return self.statistics.get_err_counter("/err/%s/%s" % (node, name))

    def in_pkt(self, src, sport, dst, dport, proto=UDP, payload=b"x" * 16, **kw):
        l4 = proto(sport=sport, dport=dport, **kw)
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=src, dst=dst)
            / l4
            / Raw(payload)
        )

    def out_pkt(self, src, sport, dst, dport, proto=UDP, payload=b"y" * 16, **kw):
        l4 = proto(sport=sport, dport=dport, **kw)
        return (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=src, dst=dst)
            / l4
            / Raw(payload)
        )

    def out2in_ok(self, pkt, in_addr, in_port):
        rx = self.send_and_expect(self.pg1, [pkt], self.pg0)[0]
        self.assertEqual(rx[IP].dst, in_addr)
        self.assertEqual(rx[IP].payload.dport, in_port)
        self.assert_packet_checksums_valid(rx)
        return rx

    def in2out(self, src, sport, dst, dport, proto=UDP, **kw):
        rx = self.send_and_expect(
            self.pg0, [self.in_pkt(src, sport, dst, dport, proto, **kw)], self.pg1
        )[0]
        self.assert_packet_checksums_valid(rx)
        return rx


class TestCgnatTranslate(CgnatPgCase):
    """CGNAT translation: UDP/TCP, EIM, drops, fragments"""

    def test_udp_out_and_back(self):
        """UDP translated out with the det44 first-choice port, reply restored"""
        h = self.host()
        rx = self.in2out(h, 5000, self.pg1.remote_ip4, 53)
        out, port = self.first_choice(h, 5000)
        self.assertEqual((rx[IP].src, rx[UDP].sport), (out, port))
        self.assertEqual((rx[IP].dst, rx[UDP].dport), (self.pg1.remote_ip4, 53))
        self.out2in_ok(self.out_pkt(self.pg1.remote_ip4, 53, out, port), h, 5000)

    def test_tcp_out_and_back(self):
        """TCP handshake through the NAT, both directions"""
        h = self.host()
        r = self.pg1.remote_ip4
        rx = self.in2out(h, 6000, r, 80, TCP, flags="S")
        out, port = self.first_choice(h, 6000)
        self.assertEqual((rx[IP].src, rx[TCP].sport), (out, port))
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="SA"), h, 6000)
        rx = self.in2out(h, 6000, r, 80, TCP, flags="A")
        self.assertEqual(rx[TCP].sport, port)

    def test_eim_same_port_any_dest(self):
        """Endpoint-independent mapping: same inside ip:port, two remotes, one outside port"""
        h = self.host()
        a = self.in2out(h, 7000, self.pg1.remote_hosts[0].ip4, 1000)
        b = self.in2out(h, 7000, self.pg1.remote_hosts[1].ip4, 2000)
        self.assertEqual((a[IP].src, a[UDP].sport), (b[IP].src, b[UDP].sport))

    def test_unmapped_inside_dropped(self):
        """Inside source in no map is dropped (no-map), never forwarded untranslated"""
        before = self.err("cgnat-in2out", "no-map")
        p = self.in_pkt("10.9.9.9", 1234, self.pg1.remote_ip4, 53)
        self.send_and_assert_no_replies(self.pg0, [p], remark="unmapped")
        self.assertEqual(self.err("cgnat-in2out", "no-map") - before, 1)

    def test_unsolicited_inbound_dropped(self):
        """Inbound to a pool ip:port with no mapping is dropped and creates no state"""
        before = self.err("cgnat-out2in", "no-mapping")
        p = self.out_pkt(self.pg1.remote_ip4, 4444, "192.0.2.1", 2000)
        self.send_and_assert_no_replies(self.pg1, [p], remark="unsolicited")
        self.assertEqual(self.err("cgnat-out2in", "no-mapping") - before, 1)
        self.assertNotIn("192.0.2.1", self.vapi.cli("show cgnat sessions"))

    def test_non_pool_outside_passes(self):
        """Outside traffic not addressed to the pool is untouched (e.g. to VPP itself)"""
        p = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
            / ICMP(type="echo-request", id=7)
        )
        rx = self.send_and_expect(self.pg1, [p], self.pg1)[0]
        self.assertEqual(rx[ICMP].type, 0)

    def test_fragments_translated(self):
        """Fragmented UDP: every fragment is translated consistently"""
        h = self.host()
        payload = bytes(range(256)) * 12  # 3072 bytes
        p = self.in_pkt(h, 8000, self.pg1.remote_ip4, 9000, payload=payload)
        frags = fragment(p, fragsize=1000)
        rx = self.send_and_expect(self.pg0, frags, self.pg1, n_rx=len(frags))
        out, port = self.first_choice(h, 8000)
        for f in rx:
            self.assertEqual(f[IP].src, out)
        whole = reassemble4(rx)
        self.assertEqual((whole[UDP].sport, whole[UDP].dport), (port, 9000))
        self.assertEqual(bytes(whole[Raw]), payload)
        self.assert_packet_checksums_valid(whole)


class TestCgnatPolicy(CgnatPgCase):
    """CGNAT policy: filtering, port collisions, session cap"""

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cgnat_set_filtering(endpoint_independent=0)
            self.vapi.cgnat_set_session_limit(per_subscriber=1000)
        super().tearDown()

    def test_address_dependent_blocks_new_remote(self):
        """Address-dependent filtering: unknown remote dropped, known remote any port allowed"""
        h = self.host()
        r1, r2 = self.pg1.remote_hosts[0].ip4, self.pg1.remote_hosts[1].ip4
        rx = self.in2out(h, 7100, r1, 1000)
        out, port = rx[IP].src, rx[UDP].sport
        before = self.err("cgnat-out2in", "filtered")
        self.send_and_assert_no_replies(
            self.pg1, [self.out_pkt(r2, 1000, out, port)], remark="r2 filtered"
        )
        self.assertEqual(self.err("cgnat-out2in", "filtered") - before, 1)
        self.out2in_ok(self.out_pkt(r1, 1001, out, port), h, 7100)

    def test_endpoint_independent_allows_any(self):
        """Endpoint-independent filtering lets any remote reach a live mapping"""
        self.vapi.cgnat_set_filtering(endpoint_independent=1)
        h = self.host()
        r1, r2 = self.pg1.remote_hosts[0].ip4, self.pg1.remote_hosts[1].ip4
        rx = self.in2out(h, 7200, r1, 1000)
        self.out2in_ok(self.out_pkt(r2, 4321, rx[IP].src, rx[UDP].sport), h, 7200)

    def test_collision_probes_within_block(self):
        """Inside ports with the same first choice get different ports in the block"""
        h = self.host()
        out, lo, hi = self.block(h)
        n = hi - lo + 1
        a = self.in2out(h, 1000, self.pg1.remote_ip4, 53)
        b = self.in2out(h, 1000 + n, self.pg1.remote_ip4, 53)
        self.assertEqual(a[UDP].sport, lo + 1000 % n)
        self.assertNotEqual(a[UDP].sport, b[UDP].sport)
        for p in (a, b):
            self.assertEqual(p[IP].src, out)
            self.assertTrue(lo <= p[UDP].sport <= hi)

    def test_session_cap(self):
        """Per-subscriber session cap: the 4th session of a capped subscriber is dropped"""
        self.vapi.cgnat_set_session_limit(per_subscriber=3)
        a, b = self.host(0), self.host(1)
        for sport in (9001, 9002, 9003):
            self.in2out(a, sport, self.pg1.remote_ip4, 53)
        before = self.err("cgnat-in2out", "cap")
        p = self.in_pkt(a, 9004, self.pg1.remote_ip4, 53)
        self.send_and_assert_no_replies(self.pg0, [p], remark="over cap")
        self.assertEqual(self.err("cgnat-in2out", "cap") - before, 1)
        self.in2out(b, 9004, self.pg1.remote_ip4, 53)


class TestCgnatExhaust(CgnatPgCase):
    """CGNAT port block exhaustion (/24 -> /32: 252 ports per subscriber)"""

    pool_plen = 32

    def test_block_exhausted(self):
        """The 253rd distinct inside port of a subscriber is dropped (exhausted)"""
        h = self.host()
        out, lo, hi = self.block(h)
        self.assertEqual(hi - lo + 1, 252)
        pkts = [self.in_pkt(h, 20000 + i, self.pg1.remote_ip4, 53) for i in range(252)]
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len({p[UDP].sport for p in rx}), 252)
        before = self.err("cgnat-in2out", "exhausted")
        p = self.in_pkt(h, 30000, self.pg1.remote_ip4, 53)
        self.send_and_assert_no_replies(self.pg0, [p], remark="exhausted")
        self.assertEqual(self.err("cgnat-in2out", "exhausted") - before, 1)


class TestCgnatIcmp(CgnatPgCase):
    """CGNAT ICMP: echo and error translation"""

    def icmp_err_out(self, src, dst, inner):
        return (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=src, dst=dst)
            / ICMP(type="dest-unreach", code="port-unreachable")
            / inner
        )

    def test_echo_out_and_back(self):
        """Echo id is translated like a port and restored on the reply"""
        h, r = self.host(), self.pg1.remote_ip4
        p = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=h, dst=r)
            / ICMP(type="echo-request", id=1234, seq=1)
            / Raw(b"ping")
        )
        rx = self.send_and_expect(self.pg0, [p], self.pg1)[0]
        out, port = self.first_choice(h, 1234)
        self.assertEqual((rx[IP].src, rx[ICMP].id), (out, port))
        self.assert_packet_checksums_valid(rx)
        reply = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=r, dst=out)
            / ICMP(type="echo-reply", id=port, seq=1)
            / Raw(b"ping")
        )
        rx = self.send_and_expect(self.pg1, [reply], self.pg0)[0]
        self.assertEqual((rx[IP].dst, rx[ICMP].id), (h, 1234))
        self.assert_packet_checksums_valid(rx)

    def test_error_for_udp_flow(self):
        """ICMP error about a translated UDP flow reaches the subscriber, inner restored"""
        h, r = self.host(), self.pg1.remote_ip4
        rx = self.in2out(h, 5000, r, 53)
        out, port = rx[IP].src, rx[UDP].sport
        router = self.pg1.remote_hosts[2].ip4
        err = self.icmp_err_out(
            router, out, IP(src=out, dst=r) / UDP(sport=port, dport=53) / Raw(b"x" * 8)
        )
        rx = self.send_and_expect(self.pg1, [err], self.pg0)[0]
        self.assertEqual(rx[IP].dst, h)
        self.assertEqual((rx[IPerror].src, rx[UDPerror].sport), (h, 5000))
        self.assert_packet_checksums_valid(rx)

    def test_error_without_flow_dropped(self):
        """ICMP error quoting an unknown flow is dropped (no-mapping)"""
        r = self.pg1.remote_ip4
        out, lo, hi = self.block(self.host())
        before = self.err("cgnat-out2in", "no-mapping")
        err = self.icmp_err_out(
            r, out, IP(src=out, dst=r) / UDP(sport=lo + 7, dport=53) / Raw(b"x" * 8)
        )
        self.send_and_assert_no_replies(self.pg1, [err], remark="unknown flow")
        self.assertEqual(self.err("cgnat-out2in", "no-mapping") - before, 1)

    def test_inside_error_translated(self):
        """ICMP error sent by a subscriber about an inbound packet is translated out"""
        self.vapi.cgnat_set_filtering(endpoint_independent=0)
        h, r = self.host(), self.pg1.remote_ip4
        rx = self.in2out(h, 5100, r, 53)
        out, port = rx[IP].src, rx[UDP].sport
        p = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=h, dst=r)
            / ICMP(type="dest-unreach", code="port-unreachable")
            / IP(src=r, dst=h)
            / UDP(sport=53, dport=5100)
            / Raw(b"x" * 8)
        )
        rx = self.send_and_expect(self.pg0, [p], self.pg1)[0]
        self.assertEqual(rx[IP].src, out)
        self.assertEqual((rx[IPerror].dst, rx[UDPerror].dport), (out, port))
        self.assert_packet_checksums_valid(rx)


class TestCgnatHairpin(CgnatPgCase):
    """CGNAT hairpinning between subscribers"""

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cgnat_set_filtering(endpoint_independent=0)
        super().tearDown()

    def test_hairpin_between_subscribers(self):
        """A reaches B via B's public ip:port; B sees A's public ip:port"""
        self.vapi.cgnat_set_filtering(endpoint_independent=1)
        a, b = self.host(0), self.host(1)
        rx = self.in2out(b, 7000, self.pg1.remote_ip4, 80)
        out_b, port_b = rx[IP].src, rx[UDP].sport
        p = self.in_pkt(a, 7500, out_b, port_b)
        rx = self.send_and_expect(self.pg0, [p], self.pg0)[0]
        out_a, port_a = self.first_choice(a, 7500)
        self.assertEqual((rx[IP].dst, rx[UDP].dport), (b, 7000))
        self.assertEqual((rx[IP].src, rx[UDP].sport), (out_a, port_a))
        self.assert_packet_checksums_valid(rx)
        # and B's reply hairpins back to A
        p = self.in_pkt(b, 7000, out_a, port_a)
        rx = self.send_and_expect(self.pg0, [p], self.pg0)[0]
        self.assertEqual((rx[IP].dst, rx[UDP].dport), (a, 7500))
        self.assertEqual((rx[IP].src, rx[UDP].sport), (out_b, port_b))


class TestCgnatTimers(CgnatPgCase):
    """CGNAT timers and expiry"""

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cgnat_set_timeouts(
                tcp_established=7440, tcp_transitory=240, udp=300, icmp=60
            )
        super().tearDown()

    def set_timeouts(self, est=2, trans=2, udp=2, icmp=2):
        self.vapi.cgnat_set_timeouts(
            tcp_established=est, tcp_transitory=trans, udp=udp, icmp=icmp
        )

    def expire(self, seconds):
        """Move VPP's clock on, then give the 1s expiry walk time to run"""
        self.virtual_sleep(seconds)
        self.sleep(1.5)

    def sessions(self):
        return [
            l for l in self.vapi.cli("show cgnat sessions").splitlines() if "thread" in l
        ]

    def test_udp_expires(self):
        """Idle UDP session and its mapping expire"""
        self.set_timeouts()
        self.in2out(self.host(), 5000, self.pg1.remote_ip4, 53)
        self.assertEqual(len(self.sessions()), 1)
        self.expire(4)
        self.assertEqual(self.sessions(), [])

    def test_tcp_fin_goes_transitory(self):
        """TCP closed by FIN both ways falls to the transitory timeout"""
        self.set_timeouts(est=60, trans=2)
        h, r = self.host(), self.pg1.remote_ip4
        rx = self.in2out(h, 6000, r, 80, TCP, flags="S")
        out, port = rx[IP].src, rx[TCP].sport
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="SA"), h, 6000)
        self.in2out(h, 6000, r, 80, TCP, flags="A")
        self.assertIn("tcp-established", self.sessions()[0])
        self.in2out(h, 6000, r, 80, TCP, flags="FA")
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="FA"), h, 6000)
        self.assertIn("tcp-transitory", self.sessions()[0])
        self.expire(4)
        self.assertEqual(self.sessions(), [])

    def test_tcp_rst_goes_transitory(self):
        """TCP reset falls to the transitory timeout"""
        self.set_timeouts(est=60, trans=2)
        h, r = self.host(), self.pg1.remote_ip4
        rx = self.in2out(h, 6100, r, 80, TCP, flags="S")
        out, port = rx[IP].src, rx[TCP].sport
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="SA"), h, 6100)
        self.in2out(h, 6100, r, 80, TCP, flags="A")
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="R"), h, 6100)
        self.assertIn("tcp-transitory", self.sessions()[0])
        self.expire(4)
        self.assertEqual(self.sessions(), [])

    def test_established_outlives_transitory(self):
        """Established TCP survives past the transitory timeout"""
        self.set_timeouts(est=60, trans=2)
        h, r = self.host(), self.pg1.remote_ip4
        rx = self.in2out(h, 6200, r, 80, TCP, flags="S")
        out, port = rx[IP].src, rx[TCP].sport
        self.out2in_ok(self.out_pkt(r, 80, out, port, TCP, flags="SA"), h, 6200)
        self.in2out(h, 6200, r, 80, TCP, flags="A")
        self.expire(4)
        self.assertEqual(len(self.sessions()), 1)

    def test_same_port_after_expiry(self):
        """After expiry the same inside port gets the same outside port"""
        self.set_timeouts()
        h = self.host()
        first = self.in2out(h, 5300, self.pg1.remote_ip4, 53)[UDP].sport
        self.expire(4)
        again = self.in2out(h, 5300, self.pg1.remote_ip4, 53)[UDP].sport
        self.assertEqual(first, again)

    def test_traffic_keeps_alive(self):
        """Traffic refreshes the timer"""
        self.set_timeouts(udp=5)
        h = self.host()
        for _ in range(4):  # ~14s in total, each gap ~3.5s
            self.in2out(h, 5400, self.pg1.remote_ip4, 53)
            self.expire(2)
        self.assertEqual(len(self.sessions()), 1)


class TestCgnatWorkers(TestCgnatTranslate):
    """CGNAT translation with 2 workers (subscriber-owned threads, handoff)"""

    vpp_worker_count = 2
    n_inside_hosts = 64

    def session_threads(self):
        out = self.vapi.cli("show cgnat sessions")
        return [int(l.split()[1]) for l in out.splitlines() if l.startswith("thread")]

    def test_many_subscribers_spread(self):
        """64 subscribers x 4 flows out and back; state spread over both workers"""
        r = self.pg1.remote_ip4
        pkts = [
            self.in_pkt(self.host(i), 10000 + j, r, 53)
            for i in range(64)
            for j in range(4)
        ]
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len(rx), 256)
        replies = [self.out_pkt(r, 53, p[IP].src, p[UDP].sport) for p in rx]
        back = self.send_and_expect(self.pg1, replies, self.pg0)
        self.assertEqual(
            sorted((p[IP].dst, p[UDP].dport) for p in back),
            sorted((self.host(i), 10000 + j) for i in range(64) for j in range(4)),
        )
        threads = self.session_threads()
        self.assertEqual(len(threads), 256)
        self.assertEqual(set(threads), {1, 2})


class TestCgnatPolicyWorkers(TestCgnatPolicy):
    """CGNAT policy with 2 workers"""

    vpp_worker_count = 2


class TestCgnatIcmpWorkers(TestCgnatIcmp):
    """CGNAT ICMP with 2 workers"""

    vpp_worker_count = 2
    n_inside_hosts = 16


class TestCgnatHairpinWorkers(TestCgnatHairpin):
    """CGNAT hairpinning with 2 workers, across subscribers owned by both"""

    vpp_worker_count = 2
    n_inside_hosts = 16

    def test_hairpin_across_threads(self):
        """Hairpin between every pair of 8 subscribers"""
        self.vapi.cgnat_set_filtering(endpoint_independent=1)
        r = self.pg1.remote_ip4
        pub = {}
        for i in range(8):
            rx = self.in2out(self.host(i), 7000, r, 80)
            pub[i] = (rx[IP].src, rx[UDP].sport)
        for i in range(8):
            for j in range(8):
                if i == j:
                    continue
                p = self.in_pkt(self.host(i), 7000, *pub[j])
                rx = self.send_and_expect(self.pg0, [p], self.pg0)[0]
                self.assertEqual((rx[IP].dst, rx[UDP].dport), (self.host(j), 7000))
                self.assertEqual((rx[IP].src, rx[UDP].sport), pub[i])


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
