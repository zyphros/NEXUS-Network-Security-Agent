"""Bounded, read-only ingestion for local security alerts and Syslog."""

import json
import logging
import os
import queue
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("network_agent.integrations")

MAX_MESSAGE_BYTES = 64 * 1024
MAX_DESCRIPTION_CHARS = 4000
DEFAULT_QUEUE_SIZE = 500

SYSLOG_SEVERITIES = (
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_syslog_message(message: bytes, sender_ip: str) -> Optional[Dict[str, Any]]:
    """Parse a bounded Syslog message into safe, display-ready fields."""
    if not message or len(message) > MAX_MESSAGE_BYTES:
        return None

    text = message.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    priority = None
    severity_number = None
    body = text
    if text.startswith("<"):
        closing = text.find(">", 1, 5)
        if closing > 1 and text[1:closing].isdigit():
            priority = int(text[1:closing])
            severity_number = priority % 8
            body = text[closing + 1 :].strip()

    severity = (
        SYSLOG_SEVERITIES[severity_number]
        if severity_number is not None
        else "unknown"
    )
    return {
        "source": "syslog",
        "observed_at": _utc_now(),
        "severity": severity,
        "severity_number": severity_number,
        "rule_id": f"syslog-pri-{priority}" if priority is not None else "syslog",
        "description": body[:MAX_DESCRIPTION_CHARS],
        "sender_ip": sender_ip,
        "agent": "",
    }


def parse_wazuh_alert(
    payload: bytes, minimum_level: int = 7
) -> Optional[Dict[str, Any]]:
    """Normalize one Wazuh alerts.json record; ignore alerts below the level."""
    if not payload or len(payload) > MAX_MESSAGE_BYTES:
        return None

    try:
        record = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict):
        return None

    rule = record.get("rule")
    agent = record.get("agent")
    rule = rule if isinstance(rule, dict) else {}
    agent = agent if isinstance(agent, dict) else {}

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        return None
    if level < minimum_level:
        return None

    description = rule.get("description") or record.get("full_log") or "Wazuh alert"
    observed_at = record.get("timestamp")
    if not isinstance(observed_at, str) or not observed_at.strip():
        observed_at = _utc_now()

    source_ip = ""
    data = record.get("data")
    if isinstance(data, dict):
        source_ip = str(data.get("srcip") or data.get("src_ip") or "")
    if not source_ip:
        source_ip = str(record.get("srcip") or "")

    return {
        "source": "wazuh",
        "observed_at": observed_at[:64],
        "severity": f"level-{level}",
        "severity_number": level,
        "rule_id": str(rule.get("id") or "unknown")[:128],
        "description": str(description)[:MAX_DESCRIPTION_CHARS],
        "sender_ip": source_ip[:128],
        "agent": str(agent.get("name") or agent.get("id") or "")[:128],
    }


def _parse_json_object(payload: bytes) -> Optional[Dict[str, Any]]:
    if not payload or len(payload) > MAX_MESSAGE_BYTES:
        return None
    try:
        record = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return record if isinstance(record, dict) else None


def _normalized_alert(
    record: Dict[str, Any],
    source: str,
    rule_id: Any,
    severity: Any,
    severity_number: Any,
    description: Any,
    observed_at: Any,
    sender_ip: Any,
) -> Dict[str, Any]:
    if isinstance(observed_at, (int, float)) and not isinstance(observed_at, bool):
        try:
            observed_at = datetime.fromtimestamp(observed_at, timezone.utc).isoformat(
                timespec="seconds"
            )
        except (OverflowError, OSError, ValueError):
            observed_at = None
    return {
        "source": source,
        "observed_at": (
            observed_at[:64]
            if isinstance(observed_at, str) and observed_at.strip()
            else _utc_now()
        ),
        "severity": str(severity)[:64] if severity is not None else "unknown",
        "severity_number": severity_number if isinstance(severity_number, int) else None,
        "rule_id": str(rule_id or "unknown")[:128],
        "description": str(description or f"{source} alert")[:MAX_DESCRIPTION_CHARS],
        "sender_ip": str(sender_ip or "")[:128],
        "agent": str(record.get("host") or record.get("sensor") or "")[:128],
    }


def parse_suricata_alert(payload: bytes) -> Optional[Dict[str, Any]]:
    """Normalize a Suricata EVE JSON alert record."""
    record = _parse_json_object(payload)
    if record is None or record.get("event_type") != "alert":
        return None
    alert = record.get("alert")
    if not isinstance(alert, dict):
        return None

    severity_number = alert.get("severity")
    try:
        severity_number = int(severity_number)
    except (TypeError, ValueError):
        severity_number = None
    severity = (
        {1: "high", 2: "medium", 3: "low"}.get(severity_number, f"level-{severity_number}")
        if severity_number is not None
        else "unknown"
    )
    return _normalized_alert(
        record,
        "suricata",
        alert.get("signature_id") or alert.get("signature"),
        severity,
        severity_number,
        alert.get("signature") or alert.get("category"),
        record.get("timestamp"),
        record.get("src_ip"),
    )


def parse_snort_alert(payload: bytes) -> Optional[Dict[str, Any]]:
    """Normalize a Snort alert_json record without retaining packet or flow data."""
    record = _parse_json_object(payload)
    if record is None or record.get("event_type") != "alert":
        return None
    alert = record.get("alert")
    if not isinstance(alert, dict):
        return None

    severity_number = alert.get("severity")
    try:
        severity_number = int(severity_number)
    except (TypeError, ValueError):
        severity_number = None
    severity = (
        {1: "high", 2: "medium", 3: "low"}.get(severity_number, f"level-{severity_number}")
        if severity_number is not None
        else "unknown"
    )
    return _normalized_alert(
        record,
        "snort",
        alert.get("signature_id") or alert.get("gid"),
        severity,
        severity_number,
        alert.get("msg") or alert.get("category"),
        record.get("timestamp"),
        record.get("src_ip"),
    )


def parse_zeek_notice(payload: bytes) -> Optional[Dict[str, Any]]:
    """Normalize one Zeek notice.log JSON record."""
    record = _parse_json_object(payload)
    if record is None or not record.get("note"):
        return None
    return _normalized_alert(
        record,
        "zeek",
        record.get("note"),
        "notice",
        None,
        record.get("msg") or record.get("sub") or record.get("note"),
        record.get("ts"),
        record.get("src"),
    )


def is_actionable_syslog_event(event: Dict[str, Any], maximum_severity: int = 4) -> bool:
    """Only treat Syslog warning-and-higher messages as dashboard alerts by default."""
    severity = event.get("severity_number")
    return isinstance(severity, int) and 0 <= severity <= maximum_severity


def _environment_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


class SecurityEventIngestor:
    """Receive Syslog UDP and tail optional JSON alerts without taking network action."""

    def __init__(
        self,
        syslog_host: str = "127.0.0.1",
        syslog_port: int = 5514,
        syslog_max_severity: int = 4,
        wazuh_alerts_file: Optional[Path] = None,
        wazuh_minimum_level: int = 7,
        suricata_eve_file: Optional[Path] = None,
        zeek_notice_file: Optional[Path] = None,
        snort_alerts_file: Optional[Path] = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        if not 1 <= syslog_port <= 65535:
            raise ValueError("Syslog UDP port must be between 1 and 65535.")
        if not 0 <= syslog_max_severity <= 7:
            raise ValueError("Syslog maximum severity must be between 0 and 7.")
        if not 0 <= wazuh_minimum_level <= 15:
            raise ValueError("Wazuh minimum level must be between 0 and 15.")
        if queue_size < 1:
            raise ValueError("Security event queue size must be positive.")

        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.syslog_max_severity = syslog_max_severity
        self.wazuh_alerts_file = wazuh_alerts_file
        self.wazuh_minimum_level = wazuh_minimum_level
        self.json_sources = (
            ("Wazuh alerts", wazuh_alerts_file, self._parse_wazuh),
            ("Suricata EVE alerts", suricata_eve_file, parse_suricata_alert),
            ("Zeek notices", zeek_notice_file, parse_zeek_notice),
            ("Snort JSON alerts", snort_alerts_file, parse_snort_alert),
        )
        self.events: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.threads = []
        self.syslog_socket: Optional[socket.socket] = None

    @property
    def enabled(self) -> bool:
        return bool(
            os.getenv("SYSLOG_UDP_ENABLED", "false").strip().lower()
            in {"1", "true", "yes", "on"}
            or self.wazuh_alerts_file
            or any(path for _, path, _ in self.json_sources[1:])
        )

    def _parse_wazuh(self, payload: bytes) -> Optional[Dict[str, Any]]:
        return parse_wazuh_alert(payload, self.wazuh_minimum_level)

    @classmethod
    def from_environment(cls) -> "SecurityEventIngestor":
        alerts_file = os.getenv("WAZUH_ALERTS_FILE", "").strip()
        suricata_file = os.getenv("SURICATA_EVE_FILE", "").strip()
        zeek_file = os.getenv("ZEEK_NOTICE_FILE", "").strip()
        snort_file = os.getenv("SNORT_ALERTS_FILE", "").strip()
        minimum_level = _environment_int("WAZUH_MINIMUM_LEVEL", 7)
        maximum_syslog_severity = _environment_int("SYSLOG_UDP_MAX_SEVERITY", 4)
        return cls(
            syslog_host=os.getenv("SYSLOG_UDP_HOST", "127.0.0.1").strip(),
            syslog_port=_environment_int("SYSLOG_UDP_PORT", 5514),
            syslog_max_severity=maximum_syslog_severity,
            wazuh_alerts_file=Path(alerts_file) if alerts_file else None,
            wazuh_minimum_level=minimum_level,
            suricata_eve_file=Path(suricata_file) if suricata_file else None,
            zeek_notice_file=Path(zeek_file) if zeek_file else None,
            snort_alerts_file=Path(snort_file) if snort_file else None,
        )

    def start(self) -> Tuple[str, ...]:
        if not self.enabled:
            return ()

        started = []
        if os.getenv("SYSLOG_UDP_ENABLED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            address_family = socket.AF_INET6 if ":" in self.syslog_host else socket.AF_INET
            listener = socket.socket(address_family, socket.SOCK_DGRAM)
            listener.settimeout(0.5)
            try:
                listener.bind((self.syslog_host, self.syslog_port))
            except OSError:
                listener.close()
                raise
            self.syslog_socket = listener
            thread = threading.Thread(
                target=self._receive_syslog,
                name="syslog-udp-ingest",
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)
            started.append(f"Syslog UDP {self.syslog_host}:{self.syslog_port}")

        configured_sources = [
            (label, path, parser)
            for label, path, parser in self.json_sources
            if path is not None
        ]
        for label, path, _ in configured_sources:
            if not path.is_file():
                self.stop()
                raise FileNotFoundError(f"{label} file does not exist: {path}")

        for label, path, parser in configured_sources:
            thread = threading.Thread(
                target=self._tail_json_file,
                args=(path, label, parser),
                name=f"{label.lower().replace(' ', '-')}-ingest",
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)
            started.append(f"{label} {path}")

        for source in started:
            logger.info("Started read-only security event ingestion: %s", source)
        return tuple(started)

    def stop(self) -> None:
        self.stop_event.set()
        if self.syslog_socket is not None:
            self.syslog_socket.close()
            self.syslog_socket = None

    def get_nowait(self) -> Dict[str, Any]:
        return self.events.get_nowait()

    def _submit(self, event: Optional[Dict[str, Any]]) -> None:
        if event is None:
            return
        try:
            self.events.put_nowait(event)
        except queue.Full:
            logger.warning("Security event queue full; dropping the newest event.")

    def _receive_syslog(self) -> None:
        listener = self.syslog_socket
        if listener is None:
            return
        while not self.stop_event.is_set():
            try:
                message, address = listener.recvfrom(MAX_MESSAGE_BYTES + 1)
            except socket.timeout:
                continue
            except OSError:
                if not self.stop_event.is_set():
                    logger.exception("Syslog UDP receiver stopped unexpectedly.")
                return
            sender_ip = str(address[0])[:128] if address else ""
            self._submit(parse_syslog_message(message, sender_ip))

    def _tail_json_file(
        self,
        path: Path,
        label: str,
        parser: Callable[[bytes], Optional[Dict[str, Any]]],
    ) -> None:
        file_handle = None
        position = 0
        file_identity = None
        try:
            while not self.stop_event.wait(0.5):
                try:
                    stat = path.stat()
                    identity = (stat.st_dev, stat.st_ino)
                    if file_handle is None or identity != file_identity or stat.st_size < position:
                        if file_handle is not None:
                            file_handle.close()
                        file_handle = path.open("rb")
                        file_handle.seek(0, os.SEEK_END)
                        position = file_handle.tell()
                        file_identity = identity
                        continue

                    file_handle.seek(position)
                    while not self.stop_event.is_set():
                        line = file_handle.readline(MAX_MESSAGE_BYTES + 1)
                        if not line:
                            break
                        if len(line) > MAX_MESSAGE_BYTES:
                            while line and not line.endswith(b"\n"):
                                line = file_handle.readline(MAX_MESSAGE_BYTES + 1)
                            position = file_handle.tell()
                            logger.warning("Skipped an oversized %s JSON line.", label)
                            continue
                        if not line.endswith(b"\n"):
                            break
                        position = file_handle.tell()
                        self._submit(parser(line))
                except FileNotFoundError:
                    logger.warning("%s file disappeared: %s", label, path)
                    self.stop_event.wait(1)
                except OSError:
                    logger.exception("Could not read %s file %s.", label, path)
                    self.stop_event.wait(1)
        finally:
            if file_handle is not None:
                file_handle.close()
