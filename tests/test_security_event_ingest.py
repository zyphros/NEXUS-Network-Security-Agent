import json
import queue
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import network_threat_detection as agent
from security_event_ingest import (
    MAX_MESSAGE_BYTES,
    SecurityEventIngestor,
    is_actionable_syslog_event,
    parse_syslog_message,
    parse_wazuh_alert,
)


class SecurityEventIngestTests(unittest.TestCase):
    def test_syslog_priority_is_normalized_to_severity_and_sender(self):
        event = parse_syslog_message(
            b"<34>Oct 16 12:00:00 firewall kernel: policy alert", "192.0.2.10"
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["source"], "syslog")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["severity_number"], 2)
        self.assertEqual(event["sender_ip"], "192.0.2.10")
        self.assertTrue(is_actionable_syslog_event(event))

    def test_syslog_without_priority_is_not_treated_as_actionable(self):
        event = parse_syslog_message(b"unstructured log message", "192.0.2.10")

        self.assertIsNotNone(event)
        self.assertEqual(event["severity"], "unknown")
        self.assertFalse(is_actionable_syslog_event(event))

    def test_syslog_debug_message_is_below_default_alert_threshold(self):
        event = parse_syslog_message(b"<15>debug event", "192.0.2.10")

        self.assertIsNotNone(event)
        self.assertEqual(event["severity_number"], 7)
        self.assertFalse(is_actionable_syslog_event(event))

    def test_oversized_syslog_datagram_is_rejected(self):
        self.assertIsNone(
            parse_syslog_message(b"x" * (MAX_MESSAGE_BYTES + 1), "192.0.2.10")
        )

    def test_wazuh_alert_is_normalized_without_copying_raw_event_fields(self):
        record = {
            "timestamp": "2026-10-16T10:00:00.000+0000",
            "rule": {"id": "5710", "level": 10, "description": "Multiple failed logins"},
            "agent": {"id": "007", "name": "web-server"},
            "data": {"srcip": "198.51.100.5"},
            "full_log": "raw message may contain unrelated sensitive values",
        }

        event = parse_wazuh_alert(json.dumps(record).encode("utf-8"))

        self.assertIsNotNone(event)
        self.assertEqual(event["source"], "wazuh")
        self.assertEqual(event["severity_number"], 10)
        self.assertEqual(event["rule_id"], "5710")
        self.assertEqual(event["sender_ip"], "198.51.100.5")
        self.assertEqual(event["agent"], "web-server")
        self.assertNotIn("full_log", event)

    def test_wazuh_alert_below_minimum_level_is_ignored(self):
        record = {"rule": {"id": "1000", "level": 3, "description": "Low-level event"}}

        self.assertIsNone(
            parse_wazuh_alert(json.dumps(record).encode("utf-8"), minimum_level=7)
        )

    def test_malformed_and_non_object_wazuh_records_are_ignored(self):
        self.assertIsNone(parse_wazuh_alert(b"{not-json"))
        self.assertIsNone(parse_wazuh_alert(b'["not", "an", "alert"]'))

    def test_wazuh_file_tailer_reads_only_new_alerts(self):
        old_record = {
            "rule": {"id": "1", "level": 10, "description": "Before startup"}
        }
        new_record = {
            "rule": {"id": "2", "level": 10, "description": "After startup"}
        }
        with tempfile.TemporaryDirectory() as directory:
            alerts_path = Path(directory) / "alerts.json"
            alerts_path.write_text(json.dumps(old_record) + "\n", encoding="utf-8")
            ingestor = SecurityEventIngestor(wazuh_alerts_file=alerts_path)
            try:
                ingestor.start()
                time.sleep(0.6)
                with alerts_path.open("a", encoding="utf-8") as alerts_file:
                    alerts_file.write(json.dumps(new_record) + "\n")

                deadline = time.monotonic() + 3
                event = None
                while time.monotonic() < deadline:
                    try:
                        event = ingestor.get_nowait()
                        break
                    except queue.Empty:
                        time.sleep(0.05)

                self.assertIsNotNone(event)
                self.assertEqual(event["rule_id"], "2")
                self.assertEqual(event["description"], "After startup")
            finally:
                ingestor.stop()

    def test_syslog_udp_listener_receives_events_on_configured_loopback_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        ingestor = SecurityEventIngestor(syslog_port=port)
        try:
            with patch.dict("os.environ", {"SYSLOG_UDP_ENABLED": "true"}):
                self.assertEqual(
                    ingestor.start(),
                    (f"Syslog UDP 127.0.0.1:{port}",),
                )
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(b"<4>firewall warning", ("127.0.0.1", port))

                deadline = time.monotonic() + 3
                event = None
                while time.monotonic() < deadline:
                    try:
                        event = ingestor.get_nowait()
                        break
                    except queue.Empty:
                        time.sleep(0.05)

                self.assertIsNotNone(event)
                self.assertEqual(event["source"], "syslog")
                self.assertEqual(event["description"], "firewall warning")
        finally:
            ingestor.stop()

    def test_monitor_forwards_syslog_alerts_to_dashboard_events(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        updates = queue.Queue()
        stop_event = threading.Event()
        snapshot = {
            "observed_at": "2026-10-16T00:00:00+00:00",
            "connections": [],
            "network_bytes": None,
        }
        with (
            patch.dict(
                "os.environ",
                {
                    "SYSLOG_UDP_ENABLED": "true",
                    "SYSLOG_UDP_HOST": "127.0.0.1",
                    "SYSLOG_UDP_PORT": str(port),
                },
            ),
            patch.object(agent, "collect_snapshot", return_value=snapshot),
            patch.object(agent, "_write_json_report", return_value=Path("test-report.json")),
        ):
            monitor = threading.Thread(
                target=agent.run_monitor,
                kwargs={
                    "interval": 1,
                    "once": False,
                    "ai_enabled": False,
                    "on_update": updates.put,
                    "stop_event": stop_event,
                },
                daemon=True,
            )
            monitor.start()
            try:
                deadline = time.monotonic() + 3
                source_started = False
                while time.monotonic() < deadline:
                    try:
                        update = updates.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if update.get("type") == "integration_status":
                        source_started = True
                        break
                self.assertTrue(source_started)

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(b"<4>firewall warning", ("127.0.0.1", port))

                deadline = time.monotonic() + 3
                alert_update = None
                while time.monotonic() < deadline:
                    try:
                        update = updates.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if update.get("type") == "alert":
                        alert_update = update
                        break

                self.assertIsNotNone(alert_update)
                event = alert_update["event"]
                self.assertEqual(event["alerts"][0]["rule"], "syslog:syslog-pri-4")
                self.assertEqual(event["ai_status"], "disabled")
                self.assertEqual(event["security_events"][0]["description"], "firewall warning")
            finally:
                stop_event.set()
                monitor.join(timeout=3)

        self.assertFalse(monitor.is_alive())

    def test_invalid_ingestion_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEventIngestor(syslog_port=70000)
        with self.assertRaises(ValueError):
            SecurityEventIngestor(wazuh_minimum_level=16)

    def test_non_integer_environment_setting_names_the_invalid_option(self):
        with patch.dict("os.environ", {"WAZUH_MINIMUM_LEVEL": "high"}):
            with self.assertRaisesRegex(ValueError, "WAZUH_MINIMUM_LEVEL must be an integer"):
                SecurityEventIngestor.from_environment()


if __name__ == "__main__":
    unittest.main()
