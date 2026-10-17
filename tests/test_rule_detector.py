import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import network_threat_detection as agent


class RuleDetectorTests(unittest.TestCase):
    def test_runtime_data_directory_uses_the_current_users_home(self):
        self.assertEqual(agent.DATA_DIR, Path.home() / ".network_security_agent" / "data")
        self.assertNotEqual(agent.DATA_DIR, agent.APP_DIR / ".network_security_agent" / "data")

    def test_snapshot_collection_uses_a_platform_neutral_connection_shape(self):
        connection = SimpleNamespace(
            raddr=SimpleNamespace(ip="192.0.2.10", port=443),
            laddr=SimpleNamespace(ip="127.0.0.1", port=50123),
            pid=None,
            status="ESTABLISHED",
        )
        with (
            patch.object(agent, "_visible_connections", return_value=[connection]),
            patch.object(agent.psutil, "net_io_counters", return_value=None),
        ):
            snapshot = agent.collect_snapshot()

        self.assertEqual(len(snapshot["connections"]), 1)
        self.assertEqual(snapshot["connections"][0]["remote_ip"], "192.0.2.10")
        self.assertEqual(snapshot["connections"][0]["local"], "127.0.0.1:50123")

    def make_connection(self, ip: str, process: str = "test.exe", status: str = "ESTABLISHED"):
        return {
            "pid": 123,
            "process": process,
            "local": "127.0.0.1:50000",
            "remote_ip": ip,
            "remote_port": 443,
            "status": status,
        }

    def make_snapshot(self, *connections):
        return {
            "observed_at": "2026-01-01T00:00:00+00:00",
            "connections": list(connections),
            "network_bytes": None,
        }

    def test_initial_snapshot_establishes_baseline_without_new_destination_alert(self):
        detector = agent.RuleDetector()
        with (
            patch.object(agent, "MAX_CONNECTIONS_ALERT", 100),
            patch.object(agent, "MAX_NEW_DESTINATIONS_ALERT", 1),
            patch.object(agent, "MAX_PROCESS_CONNECTIONS_ALERT", 100),
        ):
            result = detector.inspect(self.make_snapshot(self.make_connection("192.0.2.1")))

        self.assertEqual(result["new_destinations"], 0)
        self.assertEqual(result["alerts"], [])

    def test_connection_counts_below_configured_thresholds_do_not_alert(self):
        detector = agent.RuleDetector()
        with (
            patch.object(agent, "MAX_CONNECTIONS_ALERT", 4),
            patch.object(agent, "MAX_NEW_DESTINATIONS_ALERT", 3),
            patch.object(agent, "MAX_PROCESS_CONNECTIONS_ALERT", 3),
        ):
            result = detector.inspect(
                self.make_snapshot(
                    self.make_connection("192.0.2.1"),
                    self.make_connection("192.0.2.2"),
                )
            )

        self.assertEqual(result["alerts"], [])

    def test_threshold_alerts_are_raised_and_cooldown_prevents_duplicates(self):
        detector = agent.RuleDetector()
        with (
            patch.object(agent, "MAX_CONNECTIONS_ALERT", 2),
            patch.object(agent, "MAX_NEW_DESTINATIONS_ALERT", 1),
            patch.object(agent, "MAX_PROCESS_CONNECTIONS_ALERT", 2),
            patch("network_threat_detection.time.monotonic", side_effect=(1000.0, 1001.0, 1002.0)),
        ):
            first = self.make_snapshot(self.make_connection("192.0.2.1"))
            detector.inspect(first)

            second = self.make_snapshot(
                self.make_connection("192.0.2.1"),
                self.make_connection("192.0.2.2"),
            )
            alerts = detector.inspect(second)["alerts"]
            self.assertEqual(
                {alert["rule"] for alert in alerts},
                {"many_established_connections", "many_new_destinations", "many_connections:test.exe"},
            )

            self.assertEqual(detector.inspect(second)["alerts"], [])


if __name__ == "__main__":
    unittest.main()
