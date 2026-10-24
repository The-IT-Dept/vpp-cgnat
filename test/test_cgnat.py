#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vpp-cgnat plugin tests (run with VPP make test, see scripts/test.sh)."""

import ipaddress
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
