from __future__ import annotations

import json
import re
import socket
import sqlite3
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import time
from typing import Any

from .models import RouterSnapshot

_OID_PATTERN = re.compile(r"([A-Za-z0-9\-]+::[A-Za-z0-9\-_\.]+)")
_IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NUMERIC_OID_PATTERN = re.compile(r"((?:\.\d+){6,})")
_TRAP_VALUE_OID_PATTERN = re.compile(r"\.1\.3\.6\.1\.6\.3\.1\.1\.4\.1\.0=((?:\.\d+){6,})")

_NUMERIC_TRAP_NAMES = {
    ".1.3.6.1.6.3.1.1.5.1": "SNMPv2-MIB::coldStart",
    ".1.3.6.1.6.3.1.1.5.2": "SNMPv2-MIB::warmStart",
    ".1.3.6.1.6.3.1.1.5.3": "IF-MIB::linkDown",
    ".1.3.6.1.6.3.1.1.5.4": "IF-MIB::linkUp",
    ".1.3.6.1.6.3.1.1.5.5": "SNMPv2-MIB::authenticationFailure",
}
_TRAP_OID_VARBIND = ".1.3.6.1.6.3.1.1.4.1.0"
_UPTIME_VARBIND = ".1.3.6.1.2.1.1.3.0"
_FRIENDLY_VARBIND_LABELS = {
    ".1.3.6.1.6.3.1.1.4.3.0": "enterprise_oid",
}


def _read_tlv(payload: bytes, offset: int) -> tuple[int, int, bytes, int]:
    if offset + 2 > len(payload):
        raise ValueError("truncated ASN.1 element")
    tag = payload[offset]
    offset += 1
    first_len = payload[offset]
    offset += 1
    if first_len & 0x80:
        count = first_len & 0x7F
        if count == 0 or offset + count > len(payload):
            raise ValueError("invalid ASN.1 length")
        length = int.from_bytes(payload[offset : offset + count], "big")
        offset += count
    else:
        length = first_len
    if offset + length > len(payload):
        raise ValueError("ASN.1 element exceeds payload")
    value = payload[offset : offset + length]
    return tag, length, value, offset + length


def _decode_oid_bytes(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(value))
            value = 0
    if value:
        parts.append(str(value))
    return "." + ".".join(parts)


def _lookup_trap_name(oid: str) -> str:
    return _NUMERIC_TRAP_NAMES.get(oid, oid)


def _pretty_varbind_label(oid: str) -> str:
    return _FRIENDLY_VARBIND_LABELS.get(oid, oid)


def _decode_octet_string(data: bytes) -> str:
    for encoding in ("utf-8", "latin-1"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = data.decode("latin-1", errors="replace")
    return " ".join(text.replace("\x00", " ").split())


def _format_timeticks(value: int) -> str:
    total_seconds = value // 100
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _decode_snmp_value(tag: int, value: bytes) -> str:
    if tag == 0x06:
        oid = _decode_oid_bytes(value)
        return _lookup_trap_name(oid)
    if tag in {0x02, 0x41, 0x42, 0x46, 0x43}:
        number = int.from_bytes(value, "big", signed=(tag == 0x02))
        if tag == 0x43:
            return _format_timeticks(number)
        return str(number)
    if tag == 0x04:
        return _decode_octet_string(value)
    if tag == 0x05:
        return "null"
    if tag == 0x40 and len(value) == 4:
        return ".".join(str(part) for part in value)
    return value.hex()


def _decode_snmp_udp_packet(payload: bytes) -> tuple[str, str] | None:
    try:
        tag, _, message_value, _ = _read_tlv(payload, 0)
        if tag != 0x30:
            return None
        inner_offset = 0
        _, _, _, inner_offset = _read_tlv(message_value, inner_offset)  # version
        _, _, community_value, inner_offset = _read_tlv(message_value, inner_offset)
        pdu_tag, _, pdu_value, _ = _read_tlv(message_value, inner_offset)
        if pdu_tag not in {0xA4, 0xA7}:
            return None
        pdu_offset = 0
        _, _, _, pdu_offset = _read_tlv(pdu_value, pdu_offset)  # request-id
        _, _, _, pdu_offset = _read_tlv(pdu_value, pdu_offset)  # error-status
        _, _, _, pdu_offset = _read_tlv(pdu_value, pdu_offset)  # error-index
        list_tag, _, varbind_list, _ = _read_tlv(pdu_value, pdu_offset)
        if list_tag != 0x30:
            return None
    except ValueError:
        return None

    trap_oid = ""
    varbind_summaries: list[str] = []
    list_offset = 0
    while list_offset < len(varbind_list):
        try:
            vb_tag, _, vb_value, list_offset = _read_tlv(varbind_list, list_offset)
            if vb_tag != 0x30:
                continue
            vb_offset = 0
            oid_tag, _, oid_value, vb_offset = _read_tlv(vb_value, vb_offset)
            if oid_tag != 0x06:
                continue
            value_tag, _, value_value, _ = _read_tlv(vb_value, vb_offset)
        except ValueError:
            break
        oid = _decode_oid_bytes(oid_value)
        rendered = _decode_snmp_value(value_tag, value_value)
        if oid == _TRAP_OID_VARBIND:
            trap_oid = rendered
            continue
        if oid == _UPTIME_VARBIND:
            varbind_summaries.append(f"uptime={rendered}")
            continue
        label = _pretty_varbind_label(oid)
        varbind_summaries.append(f"{label}={rendered}")

    if not trap_oid:
        trap_oid = "snmp_trap"
    community = _decode_octet_string(community_value)
    summary_parts = [f"community: {community}"] if community else []
    summary_parts.extend(varbind_summaries[:4])
    summary = "; ".join(part for part in summary_parts if part).strip() or f"SNMP trap from {community or 'unknown community'}"
    return trap_oid, summary[:280]


def _parse_event_line(line: str) -> tuple[str, str, str]:
    oid_match = _OID_PATTERN.search(line)
    trap_oid = oid_match.group(1) if oid_match else "unknown"
    if trap_oid == "unknown":
        trap_value_match = _TRAP_VALUE_OID_PATTERN.search(line)
        if trap_value_match:
            numeric_trap = trap_value_match.group(1)
            trap_oid = _NUMERIC_TRAP_NAMES.get(numeric_trap, numeric_trap)
        else:
            numeric_match = _NUMERIC_OID_PATTERN.search(line)
            if numeric_match:
                numeric_oid = numeric_match.group(1)
                trap_oid = _NUMERIC_TRAP_NAMES.get(numeric_oid, numeric_oid)

    source_ip = "unknown"
    ips = _IP_PATTERN.findall(line)
    if ips:
        source_ip = ips[0]

    summary = line.strip()
    if len(summary) > 280:
        summary = summary[:277] + "..."

    return source_ip, trap_oid, summary


def _estimate_severity(trap_oid: str, summary: str, mapping: dict[str, str]) -> str:
    lowered_oid = (trap_oid or "").lower()
    lowered = f"{trap_oid} {summary}".lower()
    if lowered_oid in mapping:
        return mapping[lowered_oid]
    if "authenticationfailure" in lowered or "authfail" in lowered:
        return "critical"
    if "linkdown" in lowered or "coldstart" in lowered or "warmstart" in lowered:
        return "warning"
    return "info"


def _insert_event(conn: sqlite3.Connection, recorded_at: datetime, source_ip: str, trap_oid: str, summary: str, raw_line: str) -> None:
    conn.execute(
        """
        INSERT INTO router_snmp_events (
            recorded_at, source_ip, trap_oid, summary, raw_line
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            recorded_at.isoformat(),
            source_ip,
            trap_oid,
            summary[:280],
            raw_line[:1200],
        ),
    )


def _read_state(path: Path) -> tuple[int, int]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return 0, 0
    inode = int(data.get("inode", 0))
    offset = int(data.get("offset", 0))
    return inode, max(0, offset)


def _write_state(path: Path, inode: int, offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"inode": int(inode), "offset": max(0, int(offset))}
    path.write_text(json.dumps(payload), encoding="utf-8")


def ingest_router_snmp_events(
    db_path: str,
    log_path: str,
    state_file: str,
    recorded_at: datetime,
    suppress_missing_note: bool = False,
) -> tuple[int, str]:
    source = Path(log_path)
    state_path = Path(state_file)
    if not source.exists():
        if suppress_missing_note:
            return 0, ""
        return 0, f"SNMP log not found: {source}"

    current_inode = source.stat().st_ino
    last_inode, last_offset = _read_state(state_path)
    start_offset = 0 if current_inode != last_inode else last_offset

    ingested = 0
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(start_offset)
        lines = handle.readlines()
        end_offset = handle.tell()

    if lines:
        with sqlite3.connect(db_path) as conn:
            for raw_line in lines:
                text = raw_line.strip()
                if not text:
                    continue
                source_ip, trap_oid, summary = _parse_event_line(text)
                _insert_event(conn, recorded_at, source_ip, trap_oid, summary, text)
                ingested += 1

    _write_state(state_path, current_inode, end_offset)
    return ingested, f"SNMP log: {source}"


def load_router_snapshot(
    db_path: str,
    *,
    enabled: bool,
    ingest_source: str,
    window_hours: int,
    top_n: int,
    now: datetime,
    ingested_events: int = 0,
    note: str | None = None,
    oid_severity_map: dict[str, str] | None = None,
) -> RouterSnapshot:
    snapshot = RouterSnapshot(
        enabled=enabled,
        ingest_source=ingest_source,
        ingested_events=ingested_events,
        window_hours=window_hours,
        recent_events=0,
        link_down_events=0,
        auth_fail_events=0,
    )
    if note:
        snapshot.notes.append(note)
    if not enabled:
        snapshot.notes.append("Router SNMP ingest disabled.")
        return snapshot

    cutoff = (now - timedelta(hours=window_hours)).isoformat()
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT source_ip, trap_oid, summary
                FROM router_snmp_events
                WHERE recorded_at >= ?
                ORDER BY recorded_at DESC
                """,
                (cutoff,),
            ).fetchall()
    except sqlite3.OperationalError:
        snapshot.notes.append("Router SNMP table not initialized yet.")
        return snapshot

    snapshot.recent_events = len(rows)
    src_counter: Counter[str] = Counter()
    oid_counter: Counter[str] = Counter()
    sev_counter: Counter[str] = Counter()
    mapping = oid_severity_map or {}
    for source_ip, trap_oid, summary in rows:
        src_counter[source_ip or "unknown"] += 1
        oid_counter[trap_oid or "unknown"] += 1
        sev_counter[_estimate_severity(trap_oid or "", summary or "", mapping)] += 1
        lowered = f"{trap_oid} {summary}".lower()
        if "linkdown" in lowered or "if-mib::linkdown" in lowered:
            snapshot.link_down_events += 1
        if "authenticationfailure" in lowered or "authfail" in lowered:
            snapshot.auth_fail_events += 1

    snapshot.top_sources = src_counter.most_common(top_n)
    snapshot.top_trap_oids = oid_counter.most_common(top_n)
    snapshot.severity_counts = dict(sev_counter)
    if snapshot.recent_events == 0:
        snapshot.notes.append(f"No SNMP events in the last {window_hours}h window.")
    return snapshot


def format_router_snapshot_text(snapshot: RouterSnapshot, *, include_source: bool = True) -> str:
    lines = [
        f"Router SNMP enabled: {'yes' if snapshot.enabled else 'no'}",
        f"Last ingest new events: {snapshot.ingested_events}",
        f"Events in last {snapshot.window_hours}h: {snapshot.recent_events}",
        f"LinkDown events: {snapshot.link_down_events}",
        f"AuthFail events: {snapshot.auth_fail_events}",
    ]
    if snapshot.severity_counts:
        lines.append(
            "Severity counts: "
            + ", ".join(f"{name}={count}" for name, count in sorted(snapshot.severity_counts.items()))
        )
    if snapshot.top_sources:
        lines.append("Top sources: " + ", ".join(f"{src} ({count})" for src, count in snapshot.top_sources))
    if snapshot.top_trap_oids:
        lines.append("Top trap OIDs: " + ", ".join(f"{oid} ({count})" for oid, count in snapshot.top_trap_oids))
    if include_source:
        lines.append(f"Ingest source: {snapshot.ingest_source}")
    if snapshot.notes:
        lines.append("Notes: " + " | ".join(snapshot.notes))
    return "\n".join(lines)


def format_router_snapshot_json(snapshot: RouterSnapshot) -> str:
    payload: dict[str, Any] = {
        "enabled": snapshot.enabled,
        "ingest_source": snapshot.ingest_source,
        "ingested_events": snapshot.ingested_events,
        "window_hours": snapshot.window_hours,
        "recent_events": snapshot.recent_events,
        "link_down_events": snapshot.link_down_events,
        "auth_fail_events": snapshot.auth_fail_events,
        "severity_counts": snapshot.severity_counts,
        "top_sources": snapshot.top_sources,
        "top_trap_oids": snapshot.top_trap_oids,
        "notes": snapshot.notes,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def run_router_snmp_listener(db_path: str, bind_host: str, bind_port: int) -> None:
    run_router_snmp_listener_limited(
        db_path,
        bind_host,
        bind_port,
        max_events_per_minute=120,
        max_packet_bytes=4096,
        retention_days=365,
    )


def run_router_snmp_listener_limited(
    db_path: str,
    bind_host: str,
    bind_port: int,
    *,
    max_events_per_minute: int,
    max_packet_bytes: int,
    retention_days: int,
) -> None:
    window_start = time.monotonic()
    accepted_in_window = 0
    inserted_since_prune = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_host, bind_port))
        while True:
            payload, addr = sock.recvfrom(65535)
            now_monotonic = time.monotonic()
            if now_monotonic - window_start >= 60:
                window_start = now_monotonic
                accepted_in_window = 0
            if len(payload) > max_packet_bytes or accepted_in_window >= max_events_per_minute:
                continue
            accepted_in_window += 1
            now = datetime.now().astimezone()
            source_ip = addr[0] if addr else "unknown"
            decoded = _decode_snmp_udp_packet(payload)
            if decoded is not None:
                trap_oid, summary = decoded
                raw_line = payload.hex()
            else:
                text = payload.decode("utf-8", errors="replace")
                _, trap_oid, _ = _parse_event_line(text)
                summary = text.strip().replace("\n", " ")[:280] or f"SNMP packet ({len(payload)} bytes)"
                raw_line = text
            with sqlite3.connect(db_path) as conn:
                _insert_event(conn, now, source_ip, trap_oid, summary, raw_line)
                inserted_since_prune += 1
                if inserted_since_prune >= 25:
                    cutoff = (now - timedelta(days=retention_days)).isoformat()
                    conn.execute("DELETE FROM router_snmp_events WHERE recorded_at < ?", (cutoff,))
                    inserted_since_prune = 0
