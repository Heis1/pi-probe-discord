from __future__ import annotations

import socket
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from .fortigate import fortigate_dashboard_event
from .storage import init_database, save_fortigate_event, save_wan_talker


_FIELD_RE = re.compile(r'\b(?P<key>[A-Za-z_]+)=(?P<value>"[^"]*"|[^\s]+)')


def _traffic_talker(message: str) -> tuple[str, str, int] | None:
    fields = {item.group("key").lower(): item.group("value").strip('"') for item in _FIELD_RE.finditer(message)}
    if fields.get("type") != "traffic" or fields.get("subtype") != "forward" or fields.get("dstintf") != "wan1":
        return None
    source = fields.get("srcip", "")
    if not source:
        return None
    try:
        byte_count = int(fields.get("sentbyte", "0")) + int(fields.get("rcvdbyte", "0"))
    except ValueError:
        byte_count = 0
    return source, fields.get("srcname", ""), byte_count


def backfill_wan_talkers(config: object) -> int:
    """Import retained traffic logs once so historic graph points keep labels."""
    log_file = Path(str(getattr(config, "fortigate_syslog_log_file")))
    if not log_file.is_file():
        return 0
    init_database(config)
    cutoff = datetime.now().astimezone().timestamp() - (int(getattr(config, "wan_bandwidth_aggregate_retention_days", 7)) * 86400)
    inserted = 0
    batch: list[tuple[str, str, str, int]] = []
    with sqlite3.connect(str(getattr(config, "db_path"))) as conn:
        conn.execute("DELETE FROM wan_bandwidth_talkers")
        with log_file.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    continue
                try:
                    recorded_at = datetime.fromisoformat(parts[0])
                except ValueError:
                    continue
                if recorded_at.timestamp() < cutoff:
                    continue
                talker = _traffic_talker(parts[1])
                if talker is None:
                    continue
                batch.append((recorded_at.isoformat(), *talker))
                if len(batch) >= 1000:
                    conn.executemany("INSERT INTO wan_bandwidth_talkers VALUES (?, ?, ?, ?)", batch)
                    inserted += len(batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT INTO wan_bandwidth_talkers VALUES (?, ?, ?, ?)", batch)
                inserted += len(batch)
    return inserted


def run_fortigate_syslog_receiver(config: object) -> int:
    allowed = set(getattr(config, "fortigate_syslog_allowed_sources", []))
    log_file = Path(str(getattr(config, "fortigate_syslog_log_file")))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((str(getattr(config, "fortigate_syslog_bind_host")), int(getattr(config, "fortigate_syslog_port"))))
        while True:
            payload, address = server.recvfrom(16384)
            if allowed and address[0] not in allowed:
                continue
            message = payload.decode("utf-8", errors="replace").replace("\x00", " ").replace("\n", " ").strip()
            if message:
                received_at = datetime.now().astimezone()
                with log_file.open("a", encoding="utf-8") as output:
                    output.write(f"{received_at.isoformat()} source={address[0]} {message}\n")
                dashboard_event = fortigate_dashboard_event(message)
                if dashboard_event is not None:
                    save_fortigate_event(
                        config,
                        received_at,
                        dashboard_event["eventType"],
                        dashboard_event["severity"],
                        dashboard_event["source"],
                        dashboard_event["summary"],
                    )
                talker = _traffic_talker(message)
                if talker is not None:
                    save_wan_talker(config, received_at, *talker)
