"""Unit tests for src/analyzer.py.

These tests are deliberately explicit so they double as documentation: each
one shows exactly what a given log line parses into and how the aggregation
counts it. No real files are touched — every test feeds hardcoded strings to
parse_line and the resulting events to analyze_events.

Run from the project root with:  python -m unittest discover -s tests
"""

import os
import sys
import unittest

# Make the project root importable so "src.analyzer" resolves regardless of
# the working directory the test runner is launched from.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.analyzer import LogEvent, analyze_events, parse_line


class ParseLineTests(unittest.TestCase):
    """Each of the three supported formats, plus the garbage-line case."""

    def test_parses_ospf_adjacency_change(self):
        line = (
            "Feb 10 10:23:45 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 "
            "on Gig0/1 from FULL to DOWN, Neighbor Down: Dead timer expired"
        )
        event = parse_line(line)

        self.assertIsInstance(event, LogEvent)
        self.assertEqual(event.kind, "ospf_neighbor")
        self.assertEqual(event.key, "10.0.0.2")
        self.assertEqual(event.device, "R1")
        self.assertEqual(event.facility, "OSPF")
        self.assertEqual(event.severity, "5")
        self.assertIsNotNone(event.timestamp)
        self.assertEqual((event.timestamp.month, event.timestamp.day), (2, 10))
        self.assertEqual(
            (event.timestamp.hour, event.timestamp.minute, event.timestamp.second),
            (10, 23, 45),
        )

    def test_parses_interface_updown(self):
        line = (
            "Feb 10 10:24:01 R1 %LINEPROTO-5-UPDOWN: Line protocol on "
            "Interface GigabitEthernet0/1, changed state to down"
        )
        event = parse_line(line)

        self.assertIsInstance(event, LogEvent)
        self.assertEqual(event.kind, "interface")
        self.assertEqual(event.key, "GigabitEthernet0/1")
        self.assertEqual(event.device, "R1")
        self.assertEqual(event.facility, "LINEPROTO")
        self.assertEqual(event.severity, "5")

    def test_parses_auth_login_failure(self):
        line = (
            "Feb 10 10:25:12 R1 %SEC_LOGIN-4-LOGIN_FAILED: Login failed "
            "[user: admin] [Source: 10.0.0.50]"
        )
        event = parse_line(line)

        self.assertIsInstance(event, LogEvent)
        self.assertEqual(event.kind, "auth")
        # Username is preferred over the source IP as the key.
        self.assertEqual(event.key, "admin")
        self.assertEqual(event.device, "R1")
        self.assertEqual(event.facility, "SEC_LOGIN")
        self.assertEqual(event.severity, "4")

    def test_garbage_line_returns_none(self):
        self.assertIsNone(parse_line("just a garbage line that should be ignored"))
        # Blank lines are skipped too.
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   \n"))


class DeviceErrorCountingTests(unittest.TestCase):
    """Severity 0-4 counts as a device error; 5-7 (notice/info/debug) do not."""

    def test_severity_3_counts_as_device_error(self):
        line = (
            "Feb 10 10:30:00 R5 %LINK-3-UPDOWN: Interface GigabitEthernet0/2, "
            "changed state to down"
        )
        event = parse_line(line)
        self.assertEqual(event.severity, "3")

        result = analyze_events([event])
        self.assertEqual(result["device_errors"], {"R5": 1})

    def test_severity_6_does_not_count_as_device_error(self):
        line = "Feb 10 10:31:00 R5 %SYS-6-CONFIG_I: Configured from console by vty0"
        event = parse_line(line)
        self.assertEqual(event.severity, "6")

        result = analyze_events([event])
        self.assertEqual(result["device_errors"], {})


class FlapCountingTests(unittest.TestCase):
    """One neighbor and one interface cross the default threshold (3)."""

    # A neighbor that flaps 3 times, plus a quieter one that flaps once.
    # An interface that flaps 3 times, plus an auth failure for good measure.
    SAMPLE_LINES = [
        "Feb 10 10:00:01 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gig0/1 from FULL to DOWN, Dead timer expired",
        "Feb 10 10:00:05 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gig0/1 from LOADING to FULL, Loading Done",
        "Feb 10 10:00:09 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gig0/1 from FULL to DOWN, Dead timer expired",
        "Feb 10 10:00:20 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.9 on Gig0/3 from FULL to DOWN, Dead timer expired",
        "Feb 10 10:01:00 R1 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down",
        "Feb 10 10:01:04 R1 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up",
        "Feb 10 10:01:08 R1 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down",
        "Feb 10 10:02:00 R1 %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.0.0.50]",
    ]
    DEFAULT_THRESHOLD = 3

    def _build_events(self):
        events = [parse_line(line) for line in self.SAMPLE_LINES]
        # Every sample line is well-formed, so none should be dropped.
        self.assertNotIn(None, events)
        return events

    def test_neighbor_flap_counts(self):
        result = analyze_events(self._build_events())

        self.assertEqual(result["neighbor_flaps"], {"10.0.0.2": 3, "10.0.0.9": 1})
        # The noisy neighbor meets the default threshold; the quiet one does not.
        self.assertGreaterEqual(result["neighbor_flaps"]["10.0.0.2"], self.DEFAULT_THRESHOLD)
        self.assertLess(result["neighbor_flaps"]["10.0.0.9"], self.DEFAULT_THRESHOLD)

    def test_interface_flap_counts(self):
        result = analyze_events(self._build_events())

        self.assertEqual(result["interface_flaps"], {"GigabitEthernet0/1": 3})
        self.assertGreaterEqual(
            result["interface_flaps"]["GigabitEthernet0/1"], self.DEFAULT_THRESHOLD
        )

    def test_auth_failures_collected(self):
        result = analyze_events(self._build_events())

        self.assertEqual(len(result["auth_failures"]), 1)
        failure = result["auth_failures"][0]
        self.assertIsInstance(failure, LogEvent)
        self.assertEqual(failure.kind, "auth")
        self.assertEqual(failure.key, "admin")
        self.assertEqual(failure.device, "R1")


if __name__ == "__main__":
    unittest.main()
