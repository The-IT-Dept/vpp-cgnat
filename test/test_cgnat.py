#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vpp-cgnat plugin tests (run with VPP make test, see scripts/test.sh)."""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


class TestCgnatPlugin(VppTestCase):
    """CGNAT plugin loads"""

    def test_plugin_loaded(self):
        """cgnat_plugin.so is loaded"""
        out = self.vapi.cli("show plugins")
        self.assertIn("cgnat_plugin.so", out)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
