from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

UFW_STATUS_COMMAND = ["sudo", "ufw", "status", "verbose"]
JOURNALCTL_COMMAND = ["journalctl", "-k", "--since", "-24 hours", "--no-pager"]

LOG_ENTRY_RE = re.compile(r"\[UFW\s+(?P<action>[A-Z]+)\]\s+(?P<data>.*)$")
KV_RE = re.compile(r"\b([A-Z]+)=([^\s]+)")
SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


@dataclass
class UfwStatus:
    active: bool
    status_line: str
    default_incoming: str = "unknown"
    default_outgoing: str = "unknown"
    logging: str = "unknown"
    allow_rules: int = 0
    deny_rules: int = 0


@dataclass
class UfwLogEntry:
    timestamp: datetime | None
    action: str
    raw: str
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class FirewallSnapshot:
    enabled: bool
    window_hours: int
    status: UfwStatus
    total_entries: int
    blocked_entries: int
    allowed_entries: int
    top_sources: list[tuple[str, int]]
    top_ports: list[tuple[str, int]]
    top_protocols: list[tuple[str, int]]
    top_inbound_interfaces: list[tuple[str, int]]
    ipv4_events: int
    ipv6_events: int
    noisy_sources: list[tuple[str, int]]
    noisy_ports: list[tuple[str, int]]
    ssh_attempts: int
    dns_attempts: int
    notes: list[str]
    log_source: str
    log_error: str | None = None


@dataclass
class FirewallConfig:
    enabled: bool = True
    window_hours: int = 24
    top_n: int = 5
    noisy_source_threshold: int = 10
    include_allow: bool = False
    log_paths: list[str] = field(default_factory=lambda: ["/var/log/ufw.log", "/var/log/kern.log", "/var/log/syslog"])


def run_fixed_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False, timeout=20)


def parse_ufw_status_verbose(output: str) -> UfwStatus:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    status_line = next((line for line in lines if line.lower().startswith("status:")), "Status: unknown")
    active = "active" in status_line.lower()

    default_incoming = "unknown"
    default_outgoing = "unknown"
    logging = "unknown"
    allow_rules = 0
    deny_rules = 0

    for line in lines:
        low = line.lower()
        if low.startswith("default:"):
            default_match = re.search(r"([a-z]+)\s*\(incoming\)\s*,\s*([a-z]+)\s*\(outgoing\)", low)
            if default_match:
                default_incoming = default_match.group(1)
                default_outgoing = default_match.group(2)
        elif low.startswith("logging:"):
            logging = line.split(":", 1)[1].strip()
        elif line.startswith("To") and "Action" in line and "From" in line:
            continue
        elif re.search(r"\bALLOW\b", line):
            allow_rules += 1
        elif re.search(r"\bDENY\b", line):
            deny_rules += 1

    return UfwStatus(
        active=active,
        status_line=status_line,
        default_incoming=default_incoming,
        default_outgoing=default_outgoing,
        logging=logging,
        allow_rules=allow_rules,
        deny_rules=deny_rules,
    )


def _parse_syslog_timestamp(line: str, now: datetime) -> datetime | None:
    match = SYSLOG_TS_RE.match(line)
    if not match:
        return None
    mon = MONTHS.get(match.group("mon"))
    if mon is None:
        return None
    day = int(match.group("day"))
    hh, mm, ss = [int(x) for x in match.group("time").split(":")]
    try:
        dt = now.replace(month=mon, day=day, hour=hh, minute=mm, second=ss, microsecond=0)
    except ValueError:
        return None
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=dt.year - 1)
    return dt


def parse_ufw_log_line(line: str, now: datetime | None = None) -> UfwLogEntry | None:
    now = now or datetime.now().astimezone()
    match = LOG_ENTRY_RE.search(line)
    if not match:
        if "UFW" not in line:
            return None
        return UfwLogEntry(timestamp=_parse_syslog_timestamp(line, now), action="OTHER", raw=line, fields={})

    action = match.group("action")
    data = match.group("data")
    fields = {key: val for key, val in KV_RE.findall(data)}
    return UfwLogEntry(timestamp=_parse_syslog_timestamp(line, now), action=action, raw=line, fields=fields)


def _is_recent(entry: UfwLogEntry, since: datetime) -> bool:
    if entry.timestamp is None:
        return True
    return entry.timestamp >= since


def _ip_version(ip: str) -> int | None:
    try:
        value = ipaddress.ip_address(ip)
        return value.version
    except ValueError:
        return None


def _is_private_or_lan(ip: str) -> bool:
    try:
        value = ipaddress.ip_address(ip)
        return value.is_private or value.is_loopback or value.is_link_local
    except ValueError:
        return False


def _read_log_lines(paths: list[str], window_hours: int) -> tuple[list[str], str, str | None]:
    for path in paths:
        p = Path(path)
        try:
            if p.exists() and p.is_file():
                return p.read_text(encoding="utf-8", errors="replace").splitlines(), path, None
        except PermissionError:
            return [], path, f"Permission denied: {path}"
        except OSError as exc:
            return [], path, str(exc)

    journal_cmd = ["journalctl", "-k", "--since", f"-{window_hours} hours", "--no-pager"]
    result = run_fixed_command(journal_cmd)
    if result.returncode == 0:
        return result.stdout.splitlines(), "journalctl -k", None
    error = (result.stderr or result.stdout or "journalctl unavailable").strip()
    return [], "none", error


def summarize_entries(
    entries: list[UfwLogEntry],
    window_hours: int,
    top_n: int,
    noisy_source_threshold: int,
    include_allow: bool,
    log_source: str,
    enabled: bool,
    status: UfwStatus,
    log_error: str | None = None,
) -> FirewallSnapshot:
    now = datetime.now().astimezone()
    since = now - timedelta(hours=window_hours)
    recent = [entry for entry in entries if _is_recent(entry, since)]

    if not include_allow:
        recent = [entry for entry in recent if entry.action != "ALLOW"]

    source_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    proto_counter: Counter[str] = Counter()
    inbound_counter: Counter[str] = Counter()
    blocked = 0
    allowed = 0
    ipv4 = 0
    ipv6 = 0
    ssh_attempts = 0
    dns_attempts = 0
    multicast_hits = 0

    for entry in recent:
        if entry.action == "BLOCK":
            blocked += 1
        if entry.action == "ALLOW":
            allowed += 1

        src = entry.fields.get("SRC")
        dst = entry.fields.get("DST")
        dpt = entry.fields.get("DPT")
        proto = entry.fields.get("PROTO", "unknown")
        iface = entry.fields.get("IN", "unknown")

        if src:
            source_counter[src] += 1
            v = _ip_version(src)
            if v == 4:
                ipv4 += 1
            elif v == 6:
                ipv6 += 1
        if dpt:
            key = f"{dpt}/{proto}"
            port_counter[key] += 1
        proto_counter[proto] += 1
        inbound_counter[iface] += 1

        if dpt == "22":
            ssh_attempts += 1
        if dpt == "53":
            dns_attempts += 1
        if dst and (dst.startswith("224.0.0.") or dst.startswith("239.")):
            multicast_hits += 1

    noisy_sources = [(src, count) for src, count in source_counter.items() if count >= noisy_source_threshold]
    noisy_sources.sort(key=lambda x: x[1], reverse=True)
    noisy_ports = [(port, count) for port, count in port_counter.items() if count >= noisy_source_threshold]
    noisy_ports.sort(key=lambda x: x[1], reverse=True)

    notes: list[str] = []
    if not recent:
        notes.append("No recent UFW log entries found. Logging may be disabled or logs may be handled by journald.")
    if multicast_hits:
        notes.append("Likely LAN multicast noise")
    if noisy_sources:
        for src, count in noisy_sources[:top_n]:
            if _is_private_or_lan(src):
                notes.append(f"Noisy source: {src} ({count} events, private/LAN)")
            else:
                notes.append(f"External scan candidate: {src} ({count} events)")
    if noisy_ports:
        notes.append("Repeated blocked traffic on destination ports detected")
    if not notes and blocked > 0:
        notes.append("Blocked traffic is not automatically bad. It often means the firewall is doing its job.")

    return FirewallSnapshot(
        enabled=enabled,
        window_hours=window_hours,
        status=status,
        total_entries=len(recent),
        blocked_entries=blocked,
        allowed_entries=allowed,
        top_sources=source_counter.most_common(top_n),
        top_ports=port_counter.most_common(top_n),
        top_protocols=proto_counter.most_common(top_n),
        top_inbound_interfaces=inbound_counter.most_common(top_n),
        ipv4_events=ipv4,
        ipv6_events=ipv6,
        noisy_sources=noisy_sources[:top_n],
        noisy_ports=noisy_ports[:top_n],
        ssh_attempts=ssh_attempts,
        dns_attempts=dns_attempts,
        notes=notes[:6],
        log_source=log_source,
        log_error=log_error,
    )


def collect_firewall_snapshot(config: FirewallConfig) -> FirewallSnapshot:
    status_result = run_fixed_command(UFW_STATUS_COMMAND)
    status_output = (status_result.stdout or status_result.stderr or "Status: unknown").strip()
    status = parse_ufw_status_verbose(status_output)

    lines, log_source, log_error = _read_log_lines(config.log_paths, config.window_hours)
    now = datetime.now().astimezone()
    entries = [entry for line in lines if (entry := parse_ufw_log_line(line, now=now)) is not None]

    return summarize_entries(
        entries=entries,
        window_hours=config.window_hours,
        top_n=config.top_n,
        noisy_source_threshold=config.noisy_source_threshold,
        include_allow=config.include_allow,
        log_source=log_source,
        enabled=config.enabled,
        status=status,
        log_error=log_error,
    )


def format_firewall_snapshot_text(snapshot: FirewallSnapshot, detailed: bool = True) -> str:
    status_text = "✅ UFW active" if snapshot.status.active else "⚪ UFW inactive"
    policy = f"{snapshot.status.default_incoming} incoming / {snapshot.status.default_outgoing} outgoing"
    lines = [
        "🧱 Firewall Snapshot",
        f"Status: {status_text}",
        f"Default: {policy}",
        f"Logging: {snapshot.status.logging}",
        f"Recent period: {snapshot.window_hours}h",
        "",
        f"Blocks: {snapshot.blocked_entries}",
        f"Allows logged: {snapshot.allowed_entries}",
    ]

    if snapshot.top_sources:
        src, count = snapshot.top_sources[0]
        lines.append(f"Top source: {src} — {count} events")
    if snapshot.top_ports:
        port, count = snapshot.top_ports[0]
        lines.append(f"Top port: {port} — {count} events")

    if snapshot.notes:
        lines.append(f"Notes: {snapshot.notes[0]}")

    if detailed:
        lines.extend(
            [
                f"Total entries: {snapshot.total_entries}",
                f"Top protocols: {', '.join(f'{k}:{v}' for k, v in snapshot.top_protocols) or 'none'}",
                f"Top interfaces: {', '.join(f'{k}:{v}' for k, v in snapshot.top_inbound_interfaces) or 'none'}",
                f"IPv4 vs IPv6: {snapshot.ipv4_events}/{snapshot.ipv6_events}",
                f"SSH-related (22): {snapshot.ssh_attempts}",
                f"DNS-related (53): {snapshot.dns_attempts}",
                f"Log source: {snapshot.log_source}",
            ]
        )
        if snapshot.log_error:
            lines.append(f"Log read note: {snapshot.log_error}")

    return "\n".join(lines)


def format_firewall_snapshot_json(snapshot: FirewallSnapshot) -> str:
    return json.dumps(
        {
            "enabled": snapshot.enabled,
            "window_hours": snapshot.window_hours,
            "status": {
                "active": snapshot.status.active,
                "status_line": snapshot.status.status_line,
                "default_incoming": snapshot.status.default_incoming,
                "default_outgoing": snapshot.status.default_outgoing,
                "logging": snapshot.status.logging,
                "allow_rules": snapshot.status.allow_rules,
                "deny_rules": snapshot.status.deny_rules,
            },
            "totals": {
                "entries": snapshot.total_entries,
                "blocked": snapshot.blocked_entries,
                "allowed": snapshot.allowed_entries,
                "ipv4": snapshot.ipv4_events,
                "ipv6": snapshot.ipv6_events,
            },
            "top_sources": snapshot.top_sources,
            "top_ports": snapshot.top_ports,
            "top_protocols": snapshot.top_protocols,
            "top_interfaces": snapshot.top_inbound_interfaces,
            "noisy_sources": snapshot.noisy_sources,
            "noisy_ports": snapshot.noisy_ports,
            "ssh_attempts": snapshot.ssh_attempts,
            "dns_attempts": snapshot.dns_attempts,
            "notes": snapshot.notes,
            "log_source": snapshot.log_source,
            "log_error": snapshot.log_error,
        },
        indent=2,
    )
