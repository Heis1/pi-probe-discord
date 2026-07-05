from __future__ import annotations

import csv
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from importlib import metadata as importlib_metadata
import json
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
from typing import Any
from urllib.parse import urlparse

from .baselines import average, history_points_for_window
from .firewall import FirewallConfig, FirewallSnapshot, collect_firewall_snapshot
from .models import AppConfig, RouterSnapshot, SpeedResult

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
except ImportError:
    plt = None
    mdates = None
    mticker = None


DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
STATUS_FILE_NAME = "status.json"
SERVICE_NAME = "pi-probe-discord-dashboard"
MAX_REASONABLE_PING_MS = 1000.0
DIAGNOSIS_EVENT_WINDOW_HOURS = 24
DIAGNOSIS_DECISION_WINDOW_HOURS = 8
DASHBOARD_ACTION_MAX_BODY_BYTES = 16 * 1024


@dataclass
class DashboardThresholds:
    outage_download_mbps: float
    degraded_download_mbps: float
    high_ping_ms: float
    failed_test_is_outage: bool
    heatmap_good_mbps: float
    heatmap_warn_mbps: float


@dataclass
class DashboardRow:
    timestamp: datetime
    download: float | None
    upload: float | None
    ping: float | None
    speed_ok: bool = True
    speed_summary: str = ""
    speed_warnings: str = ""
    status: str = "normal"
    is_failed: bool = False
    is_outage: bool = False
    is_degraded: bool = False


@dataclass
class RouterEvent:
    timestamp: datetime
    event_type: str
    message: str
    severity: str = "info"
    source: str = ""


@dataclass
class PiholeHourlyRow:
    timestamp: datetime
    dns_queries: float | None
    blocked_queries: float | None
    blocked_percent: float | None


@dataclass
class NmapDeviceRow:
    device_id: str
    name: str
    hostname: str
    ip: str
    mac: str
    vendor: str
    status: str
    category: str
    category_label: str
    accent: str
    ports: list[dict[str, Any]]
    open_ports: list[int]
    services: list[str]
    port_count: int
    last_seen: str


def _format_relative_age(now: datetime, timestamp: datetime | None) -> str:
    if timestamp is None:
        return "unknown"
    if now.tzinfo is not None and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=now.tzinfo)
    elif now.tzinfo is None and timestamp.tzinfo is not None:
        now = now.replace(tzinfo=timestamp.tzinfo)
    delta = now - timestamp
    total_minutes = max(0, int(delta.total_seconds() // 60))
    if total_minutes < 1:
        return "just now"
    if total_minutes < 60:
        return f"{total_minutes} min ago"
    hours, minutes = divmod(total_minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m ago" if minutes else f"{hours}h ago"
    days, rem_hours = divmod(hours, 24)
    return f"{days}d {rem_hours}h ago" if rem_hours else f"{days}d ago"


def _is_extender_hint(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in ("d-link", "dlink", "extender", "repeater", "range extender", "mesh", "access point")
    )


def _key_device_role(row: NmapDeviceRow) -> str:
    text = f"{row.name} {row.hostname} {row.vendor} {row.ip}".lower()
    if "pi-probe" in text:
        return "pi-probe server"
    if _is_extender_hint(text):
        return "extender"
    if row.ip.endswith(".1") or ("router" in text and row.category == "infrastructure"):
        return "router"
    return ""


def _event_matches_key_device(event: RouterEvent, key_devices: list[dict[str, str]]) -> bool:
    text = f"{event.source} {event.message} {event.event_type}".lower()
    event_type = event.event_type.lower()
    if "linkdown" in event_type or event_type in {"snmpv2-mib::warmstart", "snmpv2-mib::coldstart"}:
        return True
    for device in key_devices:
        candidates = [
            device.get("ip", ""),
            device.get("name", ""),
            device.get("hostname", ""),
            device.get("vendor", ""),
            device.get("role", ""),
        ]
        if any(candidate and candidate.lower() in text for candidate in candidates):
            return True
    return False


def build_network_diagnosis(
    events: list[RouterEvent],
    nmap_rows: list[NmapDeviceRow],
    nmap_meta: dict[str, Any],
    *,
    now: datetime,
    router_snapshot: RouterSnapshot | None = None,
    config: AppConfig | None = None,
) -> dict[str, Any]:
    scanned_at = _coerce_datetime(nmap_meta.get("scannedAt"))
    scan_age_label = _format_relative_age(now, scanned_at)
    scan_age_minutes = None
    if scanned_at is not None:
        if now.tzinfo is not None and scanned_at.tzinfo is None:
            scanned_at = scanned_at.replace(tzinfo=now.tzinfo)
        elif now.tzinfo is None and scanned_at.tzinfo is not None:
            now = now.replace(tzinfo=scanned_at.tzinfo)
        scan_age_minutes = max(0, int((now - scanned_at).total_seconds() // 60))
    issue_window = now - timedelta(hours=DIAGNOSIS_EVENT_WINDOW_HOURS)
    decision_window = now - timedelta(hours=DIAGNOSIS_DECISION_WINDOW_HOURS)
    recent_events: list[RouterEvent] = []
    decision_events: list[RouterEvent] = []
    for event in events:
        event_time = event.timestamp
        if now.tzinfo is not None and event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=now.tzinfo)
        elif now.tzinfo is None and event_time.tzinfo is not None:
            event_time = event_time.replace(tzinfo=None)
        if event_time >= issue_window:
            recent_events.append(event)
        if event_time >= decision_window:
            decision_events.append(event)
    host_missing_context = [event for event in recent_events if event.event_type == "host_missing"]
    port_closed_context = [event for event in recent_events if event.event_type == "port_closed"]
    suspect_events_context = [
        event
        for event in recent_events
        if _is_extender_hint(f"{event.source} {event.message} {event.event_type}")
    ]
    restart_events_context = [
        event
        for event in recent_events
        if event.event_type.lower() in {"snmpv2-mib::warmstart", "snmpv2-mib::coldstart"}
    ]
    link_events_context = [event for event in recent_events if "linkdown" in event.event_type.lower()]

    host_missing = [event for event in decision_events if event.event_type == "host_missing"]
    port_closed = [event for event in decision_events if event.event_type == "port_closed"]
    restart_events = [
        event
        for event in decision_events
        if event.event_type.lower() in {"snmpv2-mib::warmstart", "snmpv2-mib::coldstart"}
    ]
    link_events = [event for event in decision_events if "linkdown" in event.event_type.lower()]
    auth_events = [event for event in decision_events if "authenticationfailure" in event.event_type.lower()]
    suspect_events = [
        event
        for event in decision_events
        if _is_extender_hint(f"{event.source} {event.message} {event.event_type}")
    ]
    suspect_devices = [
        row
        for row in nmap_rows
        if _is_extender_hint(f"{row.name} {row.hostname} {row.vendor}")
    ]
    broad_context_fault_events = (
        host_missing_context
        + port_closed_context
        + restart_events_context
        + link_events_context
        + suspect_events_context
    )
    key_devices = [
        {
            "role": role,
            "name": row.name,
            "hostname": row.hostname,
            "ip": row.ip,
            "vendor": row.vendor,
        }
        for row in nmap_rows
        if (role := _key_device_role(row))
    ]
    key_context_events = [event for event in recent_events if _event_matches_key_device(event, key_devices)]
    key_decision_events = [event for event in decision_events if _event_matches_key_device(event, key_devices)]
    ignored_context_events = max(0, len(broad_context_fault_events) - len(key_context_events))
    host_missing_context = [event for event in key_context_events if event.event_type == "host_missing"]
    port_closed_context = [event for event in key_context_events if event.event_type == "port_closed"]
    suspect_events_context = [
        event
        for event in key_context_events
        if _is_extender_hint(f"{event.source} {event.message} {event.event_type}")
    ]
    restart_events_context = [
        event
        for event in key_context_events
        if event.event_type.lower() in {"snmpv2-mib::warmstart", "snmpv2-mib::coldstart"}
    ]
    link_events_context = [event for event in key_context_events if "linkdown" in event.event_type.lower()]

    host_missing = [event for event in key_decision_events if event.event_type == "host_missing"]
    port_closed = [event for event in key_decision_events if event.event_type == "port_closed"]
    restart_events = [
        event
        for event in key_decision_events
        if event.event_type.lower() in {"snmpv2-mib::warmstart", "snmpv2-mib::coldstart"}
    ]
    link_events = [event for event in key_decision_events if "linkdown" in event.event_type.lower()]
    auth_events = [event for event in key_decision_events if "authenticationfailure" in event.event_type.lower()]
    suspect_events = [
        event
        for event in key_decision_events
        if _is_extender_hint(f"{event.source} {event.message} {event.event_type}")
    ]
    visible_suspect = bool(suspect_devices)
    inventory_fresh = bool(
        scanned_at is not None
        and scan_age_minutes is not None
        and (config is None or scan_age_minutes <= max(config.nmap_scan_minutes * 2, 90))
    )
    infra_count = sum(1 for row in nmap_rows if row.category == "infrastructure")
    fault_events = host_missing + port_closed + restart_events + link_events + suspect_events
    context_fault_events = (
        host_missing_context
        + port_closed_context
        + restart_events_context
        + link_events_context
        + suspect_events_context
    )
    latest_fault_event = max(fault_events, key=lambda event: event.timestamp) if fault_events else None
    latest_context_fault_event = max(context_fault_events, key=lambda event: event.timestamp) if context_fault_events else None
    latest_fault_age = _format_relative_age(now, latest_fault_event.timestamp if latest_fault_event else None)
    latest_context_fault_age = _format_relative_age(
        now,
        latest_context_fault_event.timestamp if latest_context_fault_event else None,
    )
    has_historical_fault_context = bool(context_fault_events and not fault_events)

    indicators: list[str] = []
    if key_devices:
        monitored = ", ".join(
            f"{device['role']}: {device['name'] or device['hostname'] or device['ip']}"
            for device in key_devices
        )
        indicators.append(f"Diagnosis is scoped to key devices only: {monitored}.")
    else:
        indicators.append("Diagnosis is scoped to key devices only, but no router, pi-probe server, or extender was confidently identified in inventory.")
    if not nmap_rows:
        indicators.append("No Nmap inventory is available yet, so the dashboard cannot confirm whether the extender is currently visible.")
    elif scanned_at is None:
        indicators.append("The latest Nmap inventory file does not include a valid scan time.")
    elif config is not None and scan_age_minutes is not None and scan_age_minutes > max(config.nmap_scan_minutes * 2, 90):
        indicators.append(f"The latest Nmap inventory is stale ({scan_age_label}); run a fresh scan before trusting device-presence conclusions.")
    else:
        indicators.append(f"The latest Nmap inventory is {scan_age_label} and shows {len(nmap_rows)} visible device(s).")

    if host_missing:
        indicators.append(
            f"{len(host_missing)} host-missing event(s) were recorded in the last {DIAGNOSIS_DECISION_WINDOW_HOURS} hours, which suggests one or more LAN devices disappeared between scans."
        )
    if port_closed:
        indicators.append(
            f"{len(port_closed)} port-closed event(s) were recorded in the last {DIAGNOSIS_DECISION_WINDOW_HOURS} hours, which can indicate an uplink or switch-port flap."
        )
    if has_historical_fault_context:
        indicators.append(
            f"Older fault evidence exists in the {DIAGNOSIS_EVENT_WINDOW_HOURS}h context window, but the last relevant event was {latest_context_fault_age}, so it is not driving the current status."
        )
    if ignored_context_events:
        indicators.append(
            f"{ignored_context_events} non-key device event(s) were ignored because they did not involve the router, pi-probe server, or extender."
        )
    if router_snapshot is not None and router_snapshot.link_down_events:
        indicators.append(f"Router SNMP recorded {router_snapshot.link_down_events} linkDown trap(s) in the last {router_snapshot.window_hours} hours.")
    elif link_events:
        indicators.append(f"{len(link_events)} recent linkDown trap(s) were recorded by router telemetry.")
    if restart_events:
        indicators.append(f"{len(restart_events)} router restart-related trap(s) were recorded, so the router or an upstream component may have rebooted.")
    if auth_events:
        indicators.append(f"{len(auth_events)} SNMP authentication-failure trap(s) were recorded; this is usually secondary noise, not the primary link fault.")
    if suspect_events:
        latest = suspect_events[-1]
        indicators.append(f"Most relevant extender clue: {latest.message}")
    if suspect_devices:
        visible = ", ".join(
            sorted({row.name or row.hostname or row.ip for row in suspect_devices if (row.name or row.hostname or row.ip)})
        )
        indicators.append(f"Extender-like device(s) currently visible in inventory: {visible}.")
    elif nmap_rows:
        indicators.append("No currently visible device in the Nmap inventory looks like a D-Link extender or access point.")

    recommendations = [
        "Run a fresh Nmap scan and compare whether the extender reappears with the same IP, MAC, and open ports.",
        "Review the event table around the outage time for host-missing, linkDown, warmStart, or coldStart entries.",
        "Capture a /networkdiag report before power-cycling gear if the fault repeats.",
    ]
    if not suspect_devices:
        recommendations.insert(0, "Add an Nmap override naming the extender clearly once it is back online, so future disappearance events are easier to identify.")

    status = "healthy"
    status_label = "No Current Fault"
    headline = "No strong extender fault indicators are visible in the recent telemetry."
    likely_cause = "No specific LAN-side fault is strongly indicated."
    confidence = "low"
    confidence_label = "Low confidence"

    active_fault = bool((host_missing or port_closed or link_events) and not visible_suspect)
    recovered_fault = bool((host_missing or port_closed or suspect_events or restart_events or link_events) and visible_suspect and inventory_fresh)
    stale_fault = bool((host_missing or port_closed or suspect_events or restart_events or link_events) and not inventory_fresh)

    if stale_fault:
        status = "stale"
        status_label = "Stale Incident"
        headline = "Older fault evidence exists, but the current inventory is not fresh enough to say whether the problem is still active."
        likely_cause = "A previous LAN-side disappearance or reboot likely occurred, but the saved view is now stale."
        confidence = "low"
        confidence_label = "Stale data"
        recommendations = [
            "Run a fresh Nmap scan before trusting the current diagnosis.",
            "Use the refreshed inventory to confirm whether the extender is back online or still absent.",
            "If this was a one-off event, the diagnosis will age out automatically after the recent-event window closes.",
        ]
    elif active_fault and host_missing and suspect_events:
        status = "critical"
        status_label = "Active Fault"
        headline = "Recent telemetry strongly suggests the extender or its uplink is still disappearing from the LAN."
        likely_cause = "The extender likely dropped off the LAN or lost its uplink during the incident."
        confidence = "high"
        confidence_label = "High confidence"
    elif active_fault:
        status = "warning"
        status_label = "Active Fault"
        headline = "Recent telemetry still points to an unresolved LAN-side disappearance or uplink flap."
        likely_cause = "A LAN-side device disappearance or uplink flap is more likely than a pure internet outage."
        confidence = "medium"
        confidence_label = "Medium confidence"
    elif recovered_fault:
        status = "resolved"
        status_label = "Recently Recovered"
        headline = "The earlier fault evidence is still recent, but the suspect device is back in the latest inventory."
        likely_cause = "The extender appears to have recovered after dropping off the LAN or losing its uplink."
        confidence = "medium"
        confidence_label = "Recovered"
        recommendations = [
            "Keep monitoring for another recurrence before power-cycling anything again.",
            "Compare the current extender IP, MAC, and open ports with the previous healthy scan to confirm it came back cleanly.",
            "If the fault repeats, capture a /networkdiag report before resetting the extender or router.",
        ]
    elif has_historical_fault_context:
        status = "healthy"
        status_label = "No Current Fault"
        headline = f"No current LAN fault is detected. The last relevant fault event was {latest_context_fault_age}, so it is being treated as history."
        likely_cause = "Previous device-disappearance evidence exists, but it is outside the current decision window."
        confidence = "medium"
        confidence_label = "Current view"
        recommendations = [
            "No immediate action is needed from the old event alone.",
            "Run a fresh Nmap scan if the dashboard looks wrong or a device still seems missing.",
            "If the fault repeats, capture /networkdiag before rebooting gear so the fresh evidence is preserved.",
        ]
    elif restart_events:
        status = "warning"
        status_label = "Needs Review"
        headline = "Router restart evidence exists, but there is not enough recent device-level evidence to isolate the extender."
        likely_cause = "Router restart evidence exists, but there is not enough device-level evidence to isolate the extender."
        confidence = "medium"
        confidence_label = "Medium confidence"

    suspect_names = sorted(
        {
            row.name or row.hostname or row.ip
            for row in suspect_devices
            if (row.name or row.hostname or row.ip)
        }
    )
    primary_suspect = suspect_names[0] if suspect_names else "No obvious extender-like device in current inventory"
    if status == "healthy":
        primary_suspect = "None active"

    evidence_items: list[dict[str, str]] = []
    if suspect_events:
        latest = suspect_events[-1]
        evidence_items.append(
            {
                "label": "Extender clue",
                "value": latest.message,
                "hint": f"{latest.event_type} from {latest.source or 'unknown source'} at {latest.timestamp.strftime('%d %b %H:%M')}",
            }
        )
    if host_missing:
        evidence_items.append(
            {
                "label": "Missing devices",
                "value": f"{len(host_missing)} host-missing event(s) in the last {DIAGNOSIS_EVENT_WINDOW_HOURS} hours",
                "hint": "These are emitted when devices vanish between Nmap scans.",
            }
        )
    if port_closed:
        evidence_items.append(
            {
                "label": "Port changes",
                "value": f"{len(port_closed)} port-closed event(s) in the last {DIAGNOSIS_EVENT_WINDOW_HOURS} hours",
                "hint": "Useful when an uplink or switch-port flaps instead of a full reboot.",
            }
        )
    if restart_events:
        evidence_items.append(
            {
                "label": "Router restart",
                "value": f"{len(restart_events)} warmStart/coldStart trap(s)",
                "hint": "Suggests the router or nearby infrastructure rebooted around the incident window.",
            }
        )
    if not evidence_items:
        if has_historical_fault_context:
            evidence_items.append(
                {
                    "label": "Historical context",
                    "value": f"Last relevant event was {latest_context_fault_age}, outside the {DIAGNOSIS_DECISION_WINDOW_HOURS}h decision window.",
                    "hint": "It remains visible as context, but it no longer drives the diagnosis headline.",
                }
            )
        else:
            evidence_items.append(
                {
                    "label": "No strong evidence",
                    "value": "Saved telemetry does not yet isolate a specific device-level failure.",
                    "hint": "Run a scan during or immediately after the next outage.",
                }
            )

    return {
        "status": status,
        "statusLabel": status_label,
        "headline": headline,
        "likelyCause": likely_cause,
        "confidence": confidence,
        "confidenceLabel": confidence_label,
        "eventWindowHours": DIAGNOSIS_EVENT_WINDOW_HOURS,
        "decisionWindowHours": DIAGNOSIS_DECISION_WINDOW_HOURS,
        "inventoryFresh": inventory_fresh,
        "latestFaultAge": latest_fault_age,
        "latestContextFaultAge": latest_context_fault_age,
        "primarySuspect": primary_suspect,
        "scanAge": scan_age_label,
        "scanAgeMinutes": scan_age_minutes,
        "inventoryDeviceCount": len(nmap_rows),
        "infrastructureCount": infra_count,
        "hostMissingCount": len(host_missing),
        "portClosedCount": len(port_closed),
        "historicalHostMissingCount": len(host_missing_context),
        "historicalPortClosedCount": len(port_closed_context),
        "historicalFaultCount": len(context_fault_events),
        "ignoredNonKeyFaultCount": ignored_context_events,
        "linkDownCount": (
            router_snapshot.link_down_events
            if router_snapshot is not None
            else len(link_events)
        ),
        "restartCount": len(restart_events),
        "authFailCount": (
            router_snapshot.auth_fail_events
            if router_snapshot is not None
            else len(auth_events)
        ),
        "suspectDevices": [
            {
                "name": row.name,
                "hostname": row.hostname,
                "ip": row.ip,
                "vendor": row.vendor,
            }
            for row in suspect_devices
        ],
        "keyDevices": key_devices,
        "recentIndicators": [
            {
                "time": event.timestamp.strftime("%d %b %Y %H:%M"),
                "eventType": event.event_type,
                "source": event.source,
                "message": event.message,
            }
            for event in (suspect_events or host_missing or port_closed or link_events or restart_events or context_fault_events)[-5:]
        ],
        "evidenceItems": evidence_items,
        "indicators": indicators,
        "recommendations": recommendations,
    }


def _format_metric(value: float | None, suffix: str, precision: int = 1) -> str:
    if value is None:
        return "n/a"
    if precision == 0:
        return f"{value:.0f} {suffix}"
    return f"{value:.{precision}f} {suffix}"


def _quantile(values: list[float], q: float) -> float | None:
    clean = sorted(values)
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    pos = (len(clean) - 1) * q
    base = int(pos)
    rest = pos - base
    if base + 1 >= len(clean):
        return clean[base]
    return clean[base] + rest * (clean[base + 1] - clean[base])


def _score_connection(avg_down: float | None, avg_up: float | None, avg_ping: float | None, pct_250: float) -> int:
    if avg_down is None or avg_up is None or avg_ping is None:
        return 0
    score = 0.0
    score += min(avg_down / 3.5, 40.0)
    score += min(avg_up / 0.8, 20.0)
    score += max(0.0, 20.0 - max(avg_ping - 3.0, 0.0) * 2.2)
    score += pct_250 * 0.2
    return max(0, min(100, round(score)))


def _safe_float(value: Any) -> float | None:
    if value in (None, "", "null"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _sanitize_ping_ms(value: Any) -> float | None:
    ping = _safe_float(value)
    if ping is None:
        return None
    if ping < 0 or ping > MAX_REASONABLE_PING_MS:
        return None
    return ping


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def _latest_timestamp(values: list[datetime | None]) -> datetime | None:
    present = [value for value in values if value is not None]
    normalized: list[datetime] = []
    for value in present:
        if value.tzinfo is None:
            normalized.append(value.replace(tzinfo=datetime.now().astimezone().tzinfo))
        else:
            normalized.append(value)
    present = normalized
    return max(present) if present else None


def _run_optional_command(command: list[str], *, timeout: int = 6) -> tuple[bool, str]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output


def _build_thresholds(config: AppConfig | None) -> DashboardThresholds:
    if config is None:
        return DashboardThresholds(
            outage_download_mbps=50.0,
            degraded_download_mbps=250.0,
            high_ping_ms=20.0,
            failed_test_is_outage=True,
            heatmap_good_mbps=320.0,
            heatmap_warn_mbps=250.0,
        )
    return DashboardThresholds(
        outage_download_mbps=config.outage_download_mbps,
        degraded_download_mbps=config.degraded_download_mbps,
        high_ping_ms=config.high_ping_ms,
        failed_test_is_outage=config.failed_test_is_outage,
        heatmap_good_mbps=config.heatmap_good_mbps,
        heatmap_warn_mbps=config.heatmap_warn_mbps,
    )


def _classify_row(row: DashboardRow, thresholds: DashboardThresholds) -> DashboardRow:
    failed = (not row.speed_ok) or row.download is None or row.upload is None or row.ping is None
    outage = False
    degraded = False
    if failed:
        outage = thresholds.failed_test_is_outage
    else:
        outage = bool(
            row.download < thresholds.outage_download_mbps or row.ping > thresholds.high_ping_ms
        )
        degraded = bool(
            not outage
            and row.download >= thresholds.outage_download_mbps
            and row.download < thresholds.degraded_download_mbps
        )
    row.is_failed = failed
    row.is_outage = outage
    row.is_degraded = degraded
    if failed:
        row.status = "failed"
    elif outage:
        row.status = "outage"
    elif degraded:
        row.status = "degraded"
    else:
        row.status = "normal"
    return row


def _merge_history(history: dict[str, list[dict[str, Any]]], now: datetime, days: int = 30) -> list[DashboardRow]:
    download_points = history_points_for_window(history, "download", now - timedelta(days=days))
    upload_points = history_points_for_window(history, "upload", now - timedelta(days=days))
    ping_points = history_points_for_window(history, "ping", now - timedelta(days=days))

    merged: dict[str, DashboardRow] = {}
    for metric_name, points in [("download", download_points), ("upload", upload_points), ("ping", ping_points)]:
        for moment, value in points:
            key = moment.isoformat()
            row = merged.get(key)
            if row is None:
                row = DashboardRow(timestamp=moment, download=None, upload=None, ping=None)
                merged[key] = row
            if metric_name == "ping":
                value = _sanitize_ping_ms(value)
            setattr(row, metric_name, value)
    return sorted(merged.values(), key=lambda row: row.timestamp)


def _rows_from_run_records(
    run_rows: list[dict[str, Any]] | None,
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    thresholds: DashboardThresholds,
    days: int = 30,
) -> list[DashboardRow]:
    if not run_rows:
        return [_classify_row(row, thresholds) for row in _merge_history(history, now, days=days)]
    rows: list[DashboardRow] = []
    cutoff = now - timedelta(days=days)
    for item in run_rows:
        recorded_at = _coerce_datetime(item.get("recorded_at"))
        if recorded_at is None or recorded_at < cutoff:
            continue
        rows.append(
            _classify_row(
                DashboardRow(
                    timestamp=recorded_at,
                    download=_safe_float(item.get("download_mbps")),
                    upload=_safe_float(item.get("upload_mbps")),
                    ping=_sanitize_ping_ms(item.get("ping_ms")),
                    speed_ok=bool(item.get("speed_ok", True)),
                    speed_summary=str(item.get("speed_summary") or ""),
                    speed_warnings=str(item.get("speed_warnings") or ""),
                ),
                thresholds,
            )
        )
    return sorted(rows, key=lambda row: row.timestamp)


def _load_router_events(config: AppConfig | None) -> list[RouterEvent]:
    if config is None:
        return []
    rows: list[RouterEvent] = []
    rows.extend(_load_router_events_from_db(config))
    rows.extend(_load_router_events_from_files(config))
    return sorted(rows, key=lambda event: event.timestamp)


def _load_router_events_from_db(config: AppConfig) -> list[RouterEvent]:
    db_path = Path(config.db_path)
    if not db_path.exists():
        return []
    cutoff = (datetime.now().astimezone() - timedelta(days=max(1, config.history_retention_days))).isoformat()
    rows: list[RouterEvent] = []
    try:
        with sqlite3.connect(db_path) as conn:
            result = conn.execute(
                """
                SELECT recorded_at, source_ip, trap_oid, summary
                FROM router_snmp_events
                WHERE recorded_at >= ?
                ORDER BY recorded_at ASC
                """,
                (cutoff,),
            ).fetchall()
    except sqlite3.Error:
        return []

    for recorded_at, source_ip, trap_oid, summary in result:
        timestamp = _coerce_datetime(recorded_at)
        if timestamp is None:
            continue
        event_type = str(trap_oid or "").strip() or "snmp_trap"
        if event_type == "unknown":
            event_type = "snmp_trap"
        rows.append(
            RouterEvent(
                timestamp=timestamp,
                event_type=event_type,
                message=str(summary or ""),
                severity=_estimate_router_event_severity(event_type, str(summary or "")),
                source=str(source_ip or "router-snmp"),
            )
        )
    return rows


def _estimate_router_event_severity(event_type: str, message: str) -> str:
    lowered = f"{event_type} {message}".lower()
    if "authenticationfailure" in lowered or "authfail" in lowered:
        return "critical"
    if "linkdown" in lowered or "warmstart" in lowered or "coldstart" in lowered:
        return "warning"
    return "info"


def _load_router_events_from_files(config: AppConfig) -> list[RouterEvent]:
    csv_path = Path(config.router_events_csv)
    json_path = Path(config.router_events_json)
    nmap_json_path = Path(config.nmap_events_json)
    rows: list[RouterEvent] = []
    if csv_path.exists():
        try:
            with csv_path.open("r", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for item in reader:
                    timestamp = _coerce_datetime(item.get("timestamp") or item.get("datetime"))
                    if timestamp is None:
                        continue
                    rows.append(
                        RouterEvent(
                            timestamp=timestamp,
                            event_type=str(item.get("event_type") or "event"),
                            message=str(item.get("message") or ""),
                            severity=str(item.get("severity") or "info"),
                            source=str(item.get("source") or ""),
                        )
                    )
        except OSError:
            return []
    if json_path.exists():
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = []
        items = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            timestamp = _coerce_datetime(item.get("timestamp") or item.get("datetime"))
            if timestamp is None:
                continue
            rows.append(
                RouterEvent(
                    timestamp=timestamp,
                    event_type=str(item.get("event_type") or "event"),
                    message=str(item.get("message") or ""),
                    severity=str(item.get("severity") or "info"),
                    source=str(item.get("source") or ""),
                )
            )
    if nmap_json_path.exists():
        try:
            raw = json.loads(nmap_json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = []
        items = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            timestamp = _coerce_datetime(item.get("timestamp") or item.get("datetime"))
            if timestamp is None:
                continue
            rows.append(
                RouterEvent(
                    timestamp=timestamp,
                    event_type=str(item.get("event_type") or "event"),
                    message=str(item.get("message") or ""),
                    severity=str(item.get("severity") or "info"),
                    source=str(item.get("source") or ""),
                )
            )
    return rows


def _load_pihole_hourly_rows(config: AppConfig | None) -> list[PiholeHourlyRow]:
    if config is None:
        return []
    path = Path(config.pihole_hourly_csv)
    if not path.exists():
        return []
    rows: list[PiholeHourlyRow] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for item in reader:
                timestamp = _coerce_datetime(item.get("datetime") or item.get("hour"))
                if timestamp is None:
                    continue
                rows.append(
                    PiholeHourlyRow(
                        timestamp=timestamp,
                        dns_queries=_safe_float(item.get("dns_queries")),
                        blocked_queries=_safe_float(item.get("blocked_queries")),
                        blocked_percent=_safe_float(item.get("blocked_percent")),
                    )
                )
    except OSError:
        return []
    return sorted(rows, key=lambda row: row.timestamp)


def _load_nmap_inventory_rows(config: AppConfig | None) -> tuple[list[NmapDeviceRow], dict[str, Any]]:
    if config is None:
        return [], {}
    path = Path(config.nmap_inventory_json)
    if not path.exists():
        return [], {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], {}
    items = raw.get("devices", []) if isinstance(raw, dict) else []
    rows: list[NmapDeviceRow] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rows.append(
            NmapDeviceRow(
                device_id=str(item.get("id") or item.get("ip") or item.get("name") or ""),
                name=str(item.get("name") or item.get("hostname") or item.get("ip") or "Unknown device"),
                hostname=str(item.get("hostname") or ""),
                ip=str(item.get("ip") or ""),
                mac=str(item.get("mac") or ""),
                vendor=str(item.get("vendor") or ""),
                status=str(item.get("status") or "up"),
                category=str(item.get("category") or "unknown"),
                category_label=str(item.get("categoryLabel") or "Unknown"),
                accent=str(item.get("accent") or "slate"),
                ports=item.get("ports") if isinstance(item.get("ports"), list) else [],
                open_ports=[int(port) for port in item.get("openPorts", []) if isinstance(port, int)],
                services=[str(service) for service in item.get("services", []) if str(service)],
                port_count=int(item.get("portCount") or 0),
                last_seen=str(item.get("lastSeen") or ""),
            )
        )
    meta = raw if isinstance(raw, dict) else {}
    return rows, {
        "scannedAt": str(meta.get("scannedAt") or ""),
        "network": str(meta.get("network") or ""),
        "deviceCount": int(meta.get("deviceCount") or len(rows)),
    }


def load_dashboard_events(config: AppConfig | None) -> list[RouterEvent]:
    return _load_router_events(config)


def load_dashboard_nmap_inventory(config: AppConfig | None) -> tuple[list[NmapDeviceRow], dict[str, Any]]:
    return _load_nmap_inventory_rows(config)


def _dashboard_action_mode(config: AppConfig | None) -> str:
    if config is None or not config.interactive_dashboard_enabled:
        return "disabled"
    if config.interactive_dashboard_api_token:
        return "token"
    return "locked"


def _ip_scope_label(ip: str) -> str:
    try:
        value = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    if value.is_loopback:
        return "Loopback"
    if value.is_link_local:
        return "Link-local"
    if value.is_private:
        return "LAN/private"
    if value.is_multicast:
        return "Multicast"
    return "External"


def _source_risk_label(ip: str, count: int, snapshot: FirewallSnapshot) -> str:
    scope = _ip_scope_label(ip)
    if scope == "External":
        return "External scan"
    if snapshot.ssh_attempts and "22/" in " ".join(port for port, _ in snapshot.top_ports[:3]):
        return "Check SSH noise"
    if count >= max(snapshot.blocked_entries * 0.45, snapshot.window_hours * 20):
        return "Dominant LAN noise"
    if scope in {"LAN/private", "Link-local", "Multicast"}:
        return "Contained LAN noise"
    return "Review source"


def _source_action_label(ip: str, matched: bool, risk: str) -> str:
    scope = _ip_scope_label(ip)
    if scope == "External":
        return "Keep blocked; review only if this repeats across SSH or admin ports."
    if matched:
        return "Confirm the device role. If trusted, tune the firewall rule or suppress this known noise."
    return "Identify this IP with a fresh scan or DHCP lease check before ignoring it."


def _build_firewall_dashboard_payload(
    snapshot: FirewallSnapshot | None,
    nmap_rows: list[NmapDeviceRow],
    *,
    error: str = "",
) -> dict[str, Any]:
    if snapshot is None:
        return {
            "available": False,
            "enabled": False,
            "error": error,
            "summary": "Firewall data unavailable",
            "sources": [],
            "ports": [],
            "notes": [],
        }

    by_ip = {row.ip: row for row in nmap_rows if row.ip}
    source_total = max(sum(count for _, count in snapshot.top_sources), snapshot.blocked_entries, 1)
    noisy_source_count = len(snapshot.noisy_sources)
    private_sources = sum(1 for ip, _ in snapshot.top_sources if _ip_scope_label(ip) != "External")
    if snapshot.blocked_entries == 0:
        summary = "No firewall noise in the current window"
        tone = "quiet"
    elif private_sources >= max(1, len(snapshot.top_sources) - 1) and snapshot.ssh_attempts == 0:
        summary = "Mostly contained LAN noise"
        tone = "contained"
    elif snapshot.ssh_attempts:
        summary = "Firewall is seeing SSH attempts"
        tone = "attention"
    else:
        summary = "Firewall activity needs review"
        tone = "review"

    sources: list[dict[str, Any]] = []
    for ip, count in snapshot.top_sources[:5]:
        row = by_ip.get(ip)
        risk = _source_risk_label(ip, count, snapshot)
        ports = row.open_ports if row is not None else []
        services = row.services if row is not None else []
        sources.append(
            {
                "ip": ip,
                "count": count,
                "share": round((count / source_total) * 100.0, 1),
                "scope": _ip_scope_label(ip),
                "risk": risk,
                "action": _source_action_label(ip, row is not None, risk),
                "matched": row is not None,
                "device": {
                    "id": row.device_id if row is not None else "",
                    "name": row.name if row is not None else "Unknown device",
                    "hostname": row.hostname if row is not None else "",
                    "mac": row.mac if row is not None else "",
                    "vendor": row.vendor if row is not None else "",
                    "category": row.category if row is not None else "unknown",
                    "categoryLabel": row.category_label if row is not None else "Unknown",
                    "accent": row.accent if row is not None else "slate",
                    "lastSeen": row.last_seen if row is not None else "",
                    "openPorts": ports,
                    "services": services,
                    "portCount": row.port_count if row is not None else 0,
                },
            }
        )

    return {
        "available": True,
        "enabled": snapshot.enabled,
        "active": snapshot.status.active,
        "tone": tone,
        "summary": summary,
        "windowHours": snapshot.window_hours,
        "blocked": snapshot.blocked_entries,
        "allowed": snapshot.allowed_entries,
        "totalEntries": snapshot.total_entries,
        "noisySources": noisy_source_count,
        "sshAttempts": snapshot.ssh_attempts,
        "dnsAttempts": snapshot.dns_attempts,
        "policy": f"{snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out",
        "logging": snapshot.status.logging,
        "logSource": snapshot.log_source,
        "logError": snapshot.log_error or "",
        "sources": sources,
        "ports": [{"port": port, "count": count} for port, count in snapshot.top_ports[:5]],
        "interfaces": [{"name": name, "count": count} for name, count in snapshot.top_inbound_interfaces[:5]],
        "notes": snapshot.notes,
    }


def _hour_label(hour: int | None) -> str:
    if hour is None:
        return "n/a"
    return f"{hour:02d}:00"


def _streaks(rows: list[DashboardRow]) -> tuple[int, str]:
    longest = 0
    current = 0
    worst_start: datetime | None = None
    current_start: datetime | None = None
    worst_end: datetime | None = None
    for row in rows:
        if row.is_outage or row.is_failed:
            current += 1
            if current_start is None:
                current_start = row.timestamp
            if current > longest:
                longest = current
                worst_start = current_start
                worst_end = row.timestamp
        else:
            current = 0
            current_start = None
    if longest and worst_start is not None and worst_end is not None:
        return longest, f"{worst_start.strftime('%d %b %H:%M')} – {worst_end.strftime('%d %b %H:%M')}"
    return 0, "No outage window recorded"


def _score_breakdown(rows: list[DashboardRow], thresholds: DashboardThresholds) -> dict[str, Any]:
    valid_rows = [row for row in rows if not row.is_failed and row.download is not None and row.upload is not None and row.ping is not None]
    downloads = [row.download for row in valid_rows if row.download is not None]
    uploads = [row.upload for row in valid_rows if row.upload is not None]
    pings = [row.ping for row in valid_rows if row.ping is not None]
    valid_count = len(valid_rows)
    pct_meeting = (
        sum(1 for value in downloads if value >= thresholds.degraded_download_mbps) / len(downloads) * 100.0
        if downloads
        else 0.0
    )
    median_down = _quantile(downloads, 0.5) or 0.0
    speed_score = min(20.0, pct_meeting / 5.0) + min(20.0, (median_down / max(thresholds.heatmap_good_mbps, 1.0)) * 20.0)

    avg_up = average(uploads) or 0.0
    up_p95 = _quantile(uploads, 0.95) or avg_up
    upload_consistency = 1.0 if up_p95 <= 0 else max(0.0, min(1.0, avg_up / up_p95))
    upload_score = min(12.0, avg_up / 4.0) + (upload_consistency * 8.0)

    avg_ping = average(pings) or 0.0
    ping_p95 = _quantile(pings, 0.95) or avg_ping
    latency_score = max(0.0, 12.0 - max(avg_ping - 3.0, 0.0) * 0.6) + max(0.0, 8.0 - max(ping_p95 - thresholds.high_ping_ms, 0.0) * 0.35)

    failed_count = sum(1 for row in rows if row.is_failed)
    outage_count = sum(1 for row in rows if row.is_outage)
    degraded_count = sum(1 for row in rows if row.is_degraded)
    penalty = 0.0
    total = max(len(rows), 1)
    penalty += (failed_count / total) * 14.0
    penalty += (outage_count / total) * 10.0
    penalty += (degraded_count / total) * 6.0
    stability_score = max(0.0, 20.0 - penalty)

    speed_score = round(max(0.0, min(40.0, speed_score)), 1)
    upload_score = round(max(0.0, min(20.0, upload_score)), 1)
    latency_score = round(max(0.0, min(20.0, latency_score)), 1)
    stability_score = round(max(0.0, min(20.0, stability_score)), 1)
    total_score = round(speed_score + upload_score + latency_score + stability_score, 1)
    return {
        "speed": speed_score,
        "upload": upload_score,
        "latency": latency_score,
        "stability": stability_score,
        "total": total_score,
        "explanation": [
            f"Speed score combines median download and the share of valid tests at or above {thresholds.degraded_download_mbps:.0f} Mbps.",
            "Upload score combines average upload and how tightly upload results cluster.",
            f"Latency score rewards low average ping and low 95th percentile ping, with {thresholds.high_ping_ms:.0f} ms as the high-ping threshold.",
            "Stability score penalises failed tests, outage-classified tests, and degraded tests.",
        ],
        "valid_tests": valid_count,
    }


def _build_dashboard_payload(
    rows: list[DashboardRow],
    events: list[RouterEvent],
    pihole_rows: list[PiholeHourlyRow],
    nmap_rows: list[NmapDeviceRow],
    nmap_meta: dict[str, Any],
    thresholds: DashboardThresholds,
    output_path: str,
    public_dashboard_url: str = "",
    config: AppConfig | None = None,
    include_firewall: bool = False,
) -> dict[str, Any]:
    downloads: list[float] = []
    uploads: list[float] = []
    pings: list[float] = []
    data: list[dict[str, Any]] = []
    for row in rows:
        if row.download is not None:
            downloads.append(row.download)
        if row.upload is not None:
            uploads.append(row.upload)
        if row.ping is not None:
            pings.append(row.ping)
        data.append(
            {
                "datetime": row.timestamp.isoformat(),
                "label": row.timestamp.strftime("%a %d %b %Y %H:%M"),
                "date": row.timestamp.strftime("%Y-%m-%d"),
                "time": row.timestamp.strftime("%H:%M"),
                "hour": row.timestamp.hour,
                "day": row.timestamp.strftime("%A"),
                "dow": row.timestamp.weekday(),
                "download": row.download,
                "upload": row.upload,
                "ping": row.ping,
                "status": row.status,
                "isFailed": row.is_failed,
                "isOutage": row.is_outage,
                "isDegraded": row.is_degraded,
                "speedOk": row.speed_ok,
                "speedSummary": row.speed_summary,
            }
        )

    start = rows[0].timestamp.strftime("%d %b %Y") if rows else "n/a"
    end = rows[-1].timestamp.strftime("%d %b %Y") if rows else "n/a"
    p05 = _quantile(downloads, 0.05)
    p95 = _quantile(downloads, 0.95)
    pct_threshold = (
        sum(1 for value in downloads if value >= thresholds.degraded_download_mbps) / len(downloads) * 100.0
        if downloads
        else 0.0
    )
    failed_count = sum(1 for row in rows if row.is_failed)
    outage_count = sum(1 for row in rows if row.is_outage)
    degraded_count = sum(1 for row in rows if row.is_degraded)
    longest_outage_streak, worst_window = _streaks(rows)

    hourly_values: list[list[float]] = [[] for _ in range(24)]
    for row in rows:
        if row.download is not None:
            hourly_values[row.timestamp.hour].append(row.download)
    hour_avg = [average(values) if values else None for values in hourly_values]
    best_hour = max(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)
    slow_hour = min(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)

    latest = rows[-1] if rows else None
    score = _score_breakdown(rows, thresholds)
    legacy_score = _score_connection(average(downloads), average(uploads), average(pings), pct_threshold)

    if latest is None:
        verdict = "no_data"
        verdict_label = "No data yet"
    elif latest.is_failed:
        verdict = "failed"
        verdict_label = "Latest test failed"
    elif latest.is_outage:
        verdict = "outage"
        verdict_label = "Outage indicators detected"
    elif latest.is_degraded:
        verdict = "degraded"
        verdict_label = "Connection below usual target"
    else:
        verdict = "normal"
        verdict_label = "Connection looks healthy"

    event_data = [
        {
            "datetime": event.timestamp.isoformat(),
            "time": event.timestamp.strftime("%d %b %Y %H:%M"),
            "eventType": event.event_type,
            "message": event.message,
            "severity": event.severity,
            "source": event.source,
        }
        for event in events[-200:]
    ]
    pihole_data = [
        {
            "datetime": row.timestamp.isoformat(),
            "hour": row.timestamp.strftime("%d %b %H:%M"),
            "dnsQueries": row.dns_queries,
            "blockedQueries": row.blocked_queries,
            "blockedPercent": row.blocked_percent,
        }
        for row in pihole_rows
    ]
    device_data = [
        {
            "id": row.device_id,
            "name": row.name,
            "hostname": row.hostname,
            "ip": row.ip,
            "mac": row.mac,
            "vendor": row.vendor,
            "status": row.status,
            "category": row.category,
            "categoryLabel": row.category_label,
            "accent": row.accent,
            "ports": row.ports,
            "openPorts": row.open_ports,
            "services": row.services,
            "portCount": row.port_count,
            "lastSeen": row.last_seen,
        }
        for row in nmap_rows
    ]
    device_counts: dict[str, int] = {}
    for row in nmap_rows:
        device_counts[row.category_label] = device_counts.get(row.category_label, 0) + 1
    action_mode = _dashboard_action_mode(config)

    generated_at = datetime.now().astimezone()
    latest_speed_at = rows[-1].timestamp if rows else None
    latest_event_at = events[-1].timestamp if events else None
    latest_pihole_at = pihole_rows[-1].timestamp if pihole_rows else None
    inventory_scanned_at = _coerce_datetime(nmap_meta.get("scannedAt"))
    diagnosis_updated_at = _latest_timestamp([latest_event_at, inventory_scanned_at, latest_pihole_at, latest_speed_at]) or generated_at

    metadata = {
        "service": SERVICE_NAME,
        "generated_at": generated_at.isoformat(),
        "dataset_start": rows[0].timestamp.isoformat() if rows else "",
        "dataset_end": rows[-1].timestamp.isoformat() if rows else "",
        "test_count": len(rows),
        "dashboard_file": Path(output_path).name,
        "version": _version_string(),
        "refreshed": {
            "dashboard": generated_at.isoformat(),
            "speed": latest_speed_at.isoformat() if latest_speed_at is not None else "",
            "events": latest_event_at.isoformat() if latest_event_at is not None else "",
            "inventory": inventory_scanned_at.isoformat() if inventory_scanned_at is not None else "",
            "pihole": latest_pihole_at.isoformat() if latest_pihole_at is not None else "",
            "diagnosis": diagnosis_updated_at.isoformat(),
        },
    }
    diagnosis = build_network_diagnosis(
        events,
        nmap_rows,
        nmap_meta,
        now=datetime.now().astimezone(),
        config=config,
    )
    firewall_snapshot: FirewallSnapshot | None = None
    firewall_error = ""
    if include_firewall and config is not None and config.firewall_enabled:
        try:
            firewall_snapshot = collect_firewall_snapshot(
                FirewallConfig(
                    enabled=config.firewall_enabled,
                    window_hours=config.firewall_window_hours,
                    top_n=config.firewall_top_n,
                    noisy_source_threshold=config.firewall_noisy_source_threshold,
                    include_allow=config.firewall_include_allow,
                    log_paths=config.firewall_log_paths,
                )
            )
        except Exception as exc:
            firewall_error = str(exc)
    firewall_data = _build_firewall_dashboard_payload(firewall_snapshot, nmap_rows, error=firewall_error)

    return {
        "data": data,
        "events": event_data,
        "pihole": pihole_data,
        "devices": device_data,
        "firewall": firewall_data,
        "inventory": {
            "scannedAt": nmap_meta.get("scannedAt", ""),
            "network": nmap_meta.get("network", ""),
            "deviceCount": nmap_meta.get("deviceCount", len(nmap_rows)),
            "categoryCounts": device_counts,
            "scanTargets": config.nmap_targets if config else "",
            "scanArguments": config.nmap_arguments if config else "",
            "scanMinutes": config.nmap_scan_minutes if config else 0,
            "actionsEnabled": action_mode in {"local", "token"},
            "actionMode": action_mode,
            "apiTokenRequired": action_mode == "token",
        },
        "stats": {
            "tests": len(rows),
            "start": start,
            "end": end,
            "avgDown": round(average(downloads) or 0.0, 1),
            "medianDown": round(_quantile(downloads, 0.5) or 0.0, 1),
            "avgUp": round(average(uploads) or 0.0, 1),
            "avgPing": round(average(pings) or 0.0, 2),
            "p05": round(p05 or 0.0, 1),
            "p95": round(p95 or 0.0, 1),
            "pctThreshold": round(pct_threshold, 1),
            "thresholdMbps": thresholds.degraded_download_mbps,
            "failedCount": failed_count,
            "outageCount": outage_count,
            "degradedCount": degraded_count,
            "longestOutageStreak": longest_outage_streak,
            "worstWindow": worst_window,
            "bestHour": _hour_label(best_hour[0]) if best_hour else "n/a",
            "bestHourMbps": round(best_hour[1], 1) if best_hour else None,
            "slowHour": _hour_label(slow_hour[0]) if slow_hour else "n/a",
            "slowHourMbps": round(slow_hour[1], 1) if slow_hour else None,
            "legacyScore": legacy_score,
            "publicDashboardUrl": public_dashboard_url,
            "latestStatus": latest.status if latest else "none",
            "latestDownload": latest.download if latest else None,
            "latestUpload": latest.upload if latest else None,
            "latestPing": latest.ping if latest else None,
            "verdict": verdict,
            "verdictLabel": verdict_label,
        },
        "score": score,
        "diagnosis": diagnosis,
        "thresholds": {
            "outageDownloadMbps": thresholds.outage_download_mbps,
            "degradedDownloadMbps": thresholds.degraded_download_mbps,
            "highPingMs": thresholds.high_ping_ms,
            "failedTestIsOutage": thresholds.failed_test_is_outage,
            "heatmapGoodMbps": thresholds.heatmap_good_mbps,
            "heatmapWarnMbps": thresholds.heatmap_warn_mbps,
        },
        "meta": metadata,
    }


def build_dashboard_summary(
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    config: AppConfig | None = None,
    run_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    thresholds = _build_thresholds(config)
    rows = _rows_from_run_records(run_rows, history, now, thresholds, days=30)
    payload = _build_dashboard_payload(
        rows,
        [],
        [],
        [],
        {},
        thresholds,
        output_path="dashboard.html",
        public_dashboard_url=(config.public_dashboard_url if config else ""),
        config=config,
    )
    return {
        "stats": payload["stats"],
        "score": payload["score"],
        "thresholds": payload["thresholds"],
    }


def generate_interactive_dashboard(
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    output_path: str,
    config: AppConfig | None = None,
    run_rows: list[dict[str, Any]] | None = None,
    router_events: list[RouterEvent] | None = None,
    pihole_rows: list[PiholeHourlyRow] | None = None,
) -> tuple[bool, str]:
    thresholds = _build_thresholds(config)
    rows = _rows_from_run_records(run_rows, history, now, thresholds, days=30)
    if not rows:
        return False, "No speed data available for interactive dashboard"

    event_rows = router_events if router_events is not None else _load_router_events(config)
    dns_rows = pihole_rows if pihole_rows is not None else _load_pihole_hourly_rows(config)
    nmap_rows, nmap_meta = _load_nmap_inventory_rows(config)
    payload = _build_dashboard_payload(
        rows,
        event_rows,
        dns_rows,
        nmap_rows,
        nmap_meta,
        thresholds,
        output_path=output_path,
        public_dashboard_url=(config.public_dashboard_url if config else ""),
        config=config,
        include_firewall=True,
    )
    html = _render_interactive_dashboard_html(payload)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    output.with_name(STATUS_FILE_NAME).write_text(json.dumps(payload["meta"], indent=2), encoding="utf-8")
    return True, f"Interactive dashboard written to {output}"


def _render_interactive_dashboard_html(payload: dict[str, Any]) -> str:
    payload_json = (
        json.dumps(payload)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pi Probe NBN Interactive Dashboard</title>
<style>
:root {
  --bg: #07101c;
  --panel: rgba(16, 24, 39, 0.88);
  --panel-2: rgba(12, 20, 33, 0.72);
  --border: rgba(148, 163, 184, 0.18);
  --text: #f8fafc;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --accent-2: #22c55e;
  --warn: #f59e0b;
  --danger: #ef4444;
}
body.theme-clean {
  --bg: #e8eef7;
  --panel: rgba(255,255,255,.92);
  --panel-2: rgba(255,255,255,.84);
  --border: rgba(30, 41, 59, .12);
  --text: #0f172a;
  --muted: #475569;
  --accent: #0284c7;
  --accent-2: #15803d;
  --warn: #d97706;
  --danger: #dc2626;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--text);
  background:
    radial-gradient(circle at top left, rgba(56,189,248,.18), transparent 28rem),
    radial-gradient(circle at top right, rgba(34,197,94,.12), transparent 26rem),
    linear-gradient(180deg, #020617, var(--bg));
  min-height: 100vh;
}
body.theme-clean { background: linear-gradient(180deg, #f8fafc, var(--bg)); }
.wrap { max-width: 1720px; margin: 0 auto; padding: 24px; }
.hero { display:grid; grid-template-columns: 1.2fr .8fr; gap: 18px; margin-bottom: 18px; }
.hero, .panel, .kpi { backdrop-filter: blur(12px); }
.panel, .kpi, .controls {
  border: 1px solid var(--border);
  background: var(--panel);
  border-radius: 22px;
  box-shadow: 0 24px 70px rgba(0,0,0,.18);
}
.hero-main { padding: 20px 22px; }
.hero-main h1 { margin: 0; font-size: clamp(28px, 4vw, 48px); letter-spacing: -.04em; }
.hero-main .sub { margin-top: 6px; color: var(--muted); font-size: 15px; }
.hero-meta { display:flex; flex-wrap:wrap; gap: 10px; margin-top: 12px; }
.hero-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 18px; }
.kpi { padding: 16px; min-height: 112px; }
.kpi .label { color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.kpi .value { margin-top: 10px; font-size: 30px; font-weight: 900; letter-spacing: -.05em; }
.kpi .sub { margin-top: 8px; color: var(--muted); font-size: 12px; line-height: 1.35; }
.hero-side { padding: 20px 22px; display:flex; flex-direction:column; gap: 14px; }
.hero-side.status-normal {
  border-color: rgba(34,197,94,.42);
  box-shadow: 0 24px 70px rgba(34,197,94,.10);
}
.hero-side.status-degraded {
  border-color: rgba(245,158,11,.42);
  box-shadow: 0 24px 70px rgba(245,158,11,.10);
}
.hero-side.status-outage, .hero-side.status-failed {
  border-color: rgba(239,68,68,.42);
  box-shadow: 0 24px 70px rgba(239,68,68,.12);
}
.hero-side.status-no_data {
  border-color: rgba(148,163,184,.28);
}
.verdict-badge {
  display:inline-flex; align-items:center; align-self:flex-start;
  padding: 7px 12px; border-radius: 999px;
  border: 1px solid var(--border);
  font-size: 12px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase;
}
.hero-side.status-normal .verdict-badge { background: rgba(34,197,94,.14); color: #86efac; }
.hero-side.status-degraded .verdict-badge { background: rgba(245,158,11,.16); color: #fcd34d; }
.hero-side.status-outage .verdict-badge, .hero-side.status-failed .verdict-badge { background: rgba(239,68,68,.16); color: #fca5a5; }
.hero-side.status-no_data .verdict-badge { background: rgba(148,163,184,.14); color: #cbd5e1; }
.hero-side .verdict { font-size: 26px; font-weight: 900; letter-spacing: -.03em; line-height: 1.1; }
.hero-side .copy { color: var(--muted); font-size: 14px; line-height: 1.45; }
.hero-side .chiprow { display:flex; flex-wrap:wrap; gap: 10px; }
.chip { padding: 9px 12px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); font-size: 13px; }
.controls { display:grid; grid-template-columns: repeat(6, 1fr); gap: 12px; padding: 14px; margin-bottom: 18px; }
label { display:block; color: var(--muted); font-size: 12px; font-weight: 700; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .06em; }
select, input { width: 100%; border: 1px solid var(--border); background: rgba(2,6,23,.28); color: var(--text); border-radius: 12px; padding: 10px 11px; }
body.theme-clean select, body.theme-clean input { background: rgba(255,255,255,.72); }
.diag-section, .firewall-section { margin-bottom: 18px; }
.grid { display:grid; grid-template-columns: minmax(0, 1.3fr) minmax(360px, .95fr); gap: 18px; align-items:start; }
.stack { display:grid; gap: 18px; }
.panel { padding: 18px; }
.panel, .kpi, .controls, .device-cluster, .diag-hero, .diag-stat, .diag-item, .diag-sidebox, .summary-card, .score-card {
  transition: border-color .18s ease, transform .18s ease, box-shadow .18s ease;
}
.panel:hover, .kpi:hover {
  border-color: rgba(148, 163, 184, .26);
}
.score-section { margin-top: 18px; }
.panel-head {
  margin-bottom: 12px;
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap: 12px;
}
.panel-head h2 { margin: 0; font-size: 24px; letter-spacing: -.03em; }
.panel-head p { margin: 4px 0 0; color: var(--muted); font-size: 13px; line-height: 1.4; }
.panel-stamp {
  flex: 0 0 auto;
  align-self:flex-start;
  padding: 7px 11px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--panel-2);
  color: var(--muted);
  font-size: 11px;
  font-weight: 800;
  white-space: nowrap;
}
.chart { height: 390px; }
.chart-small { height: 320px; }
.device-map {
  min-height: 330px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.device-cluster {
  border: 1px solid var(--border);
  border-radius: 18px;
  background: var(--panel-2);
  padding: 14px;
}
.cluster-head {
  display:flex; justify-content:space-between; align-items:center; gap:10px;
  margin-bottom: 12px;
}
.cluster-title { font-size: 14px; font-weight: 800; letter-spacing: -.01em; }
.cluster-count {
  border-radius: 999px; padding: 4px 9px; border: 1px solid var(--border);
  color: var(--muted); font-size: 11px; font-weight: 800;
}
.device-list { display:grid; gap: 10px; }
.device-card {
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 14px;
  padding: 11px 12px;
  background: rgba(2,6,23,.18);
}
.device-card.cyan { border-left-color: #38bdf8; }
.device-card.green { border-left-color: #22c55e; }
.device-card.blue { border-left-color: #60a5fa; }
.device-card.amber { border-left-color: #f59e0b; }
.device-card.violet { border-left-color: #8b5cf6; }
.device-card.orange { border-left-color: #f97316; }
.device-card.slate { border-left-color: #94a3b8; }
.device-name { font-size: 14px; font-weight: 800; line-height: 1.2; }
.device-ip { margin-top: 3px; color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.device-meta, .device-services {
  margin-top: 8px;
  display:flex; flex-wrap:wrap; gap: 6px;
}
.device-chip {
  display:inline-flex; align-items:center;
  border-radius: 999px; padding: 4px 8px;
  background: rgba(148,163,184,.10);
  border: 1px solid var(--border);
  font-size: 11px; color: var(--muted); font-weight: 700;
}
.device-chip.primary { color: var(--text); }
.device-chip.fresh { color: #86efac; }
.device-chip.aging { color: #fcd34d; }
.device-chip.stale { color: #fca5a5; }
.device-editor {
  margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border);
  display:grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.device-editor label {
  display:block; color: var(--muted); font-size: 11px; font-weight: 700; margin-bottom: 4px;
}
.device-editor input, .device-editor select {
  width: 100%; border-radius: 10px; border: 1px solid var(--border);
  background: var(--panel-2); color: var(--text); padding: 8px 10px; font-size: 12px;
}
.device-editor .span-2 { grid-column: 1 / -1; }
.device-actions { display:flex; gap: 8px; grid-column: 1 / -1; }
.device-tool-row { display:flex; gap: 8px; grid-column: 1 / -1; }
.mini-button {
  appearance:none; border: 1px solid var(--border); border-radius: 10px;
  background: var(--panel-2); color: var(--text); padding: 8px 10px; font-size: 12px; font-weight: 800; cursor: pointer;
}
.mini-button.primary { background: rgba(56,189,248,.18); }
.mini-button.warn { background: rgba(245,158,11,.14); }
.device-status { grid-column: 1 / -1; color: var(--muted); font-size: 11px; line-height: 1.4; min-height: 16px; }
.chart-meta { display:flex; flex-wrap:wrap; gap: 10px; margin: 10px 0 0; }
.chart-summary {
  display:grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin: 12px 0 10px;
}
.summary-card {
  border: 1px solid var(--border);
  border-radius: 14px;
  background: var(--panel-2);
  padding: 12px 13px;
}
.summary-card .label { color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.summary-card .value { margin-top: 7px; font-size: 16px; font-weight: 900; letter-spacing: -.02em; }
.summary-card .mini { margin-top: 5px; color: var(--muted); font-size: 12px; line-height: 1.4; }
.legend-chip {
  display:inline-flex; align-items:center; gap: 8px;
  padding: 7px 11px; border-radius: 999px;
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--muted); font-size: 12px; font-weight: 700;
}
.legend-swatch { width: 12px; height: 12px; border-radius: 999px; display:inline-block; }
.action-row { display:flex; flex-wrap:wrap; gap: 10px; align-items:center; margin: 12px 0 14px; }
.action-button {
  appearance:none; border: 1px solid var(--border); border-radius: 12px;
  background: linear-gradient(135deg, rgba(56,189,248,.20), rgba(34,197,94,.18));
  color: var(--text); padding: 10px 14px; font-size: 13px; font-weight: 800;
  cursor: pointer; transition: transform .15s ease, opacity .15s ease, border-color .15s ease;
}
.action-button:hover { transform: translateY(-1px); border-color: rgba(56,189,248,.45); }
.action-button:disabled { opacity: .6; cursor: progress; transform: none; }
.helper-text { color: var(--muted); font-size: 12px; line-height: 1.4; }
.table-wrap { overflow:auto; border-radius: 16px; border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.time-cell { white-space: nowrap; min-width: 92px; }
.type-cell { min-width: 146px; font-weight: 700; }
.source-cell { white-space: nowrap; min-width: 110px; font-variant-numeric: tabular-nums; }
.message-cell { min-width: 280px; color: var(--text); overflow-wrap: anywhere; line-height: 1.4; }
.severity-pill {
  display:inline-flex; align-items:center; justify-content:center;
  min-width: 72px; padding: 5px 10px; border-radius: 999px;
  border: 1px solid var(--border); font-size: 11px; font-weight: 800;
  text-transform: uppercase; letter-spacing: .08em;
}
.severity-pill.info { color: #7dd3fc; background: rgba(56,189,248,.14); }
.severity-pill.warning { color: #fbbf24; background: rgba(245,158,11,.14); }
.severity-pill.critical { color: #fca5a5; background: rgba(239,68,68,.14); }
.table-empty { color: var(--muted); text-align: center; padding: 18px; }
.score-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px; }
.score-card { padding: 14px; border: 1px solid var(--border); border-radius: 16px; background: var(--panel-2); }
.score-card b { display:block; font-size: 26px; margin-top: 6px; }
.score-card .mini { margin-top: 6px; color: var(--muted); font-size: 12px; line-height: 1.35; }
.score-card.total-card {
  background: linear-gradient(135deg, rgba(56,189,248,.12), rgba(34,197,94,.10));
  border-color: rgba(56,189,248,.28);
}
.score-card.total-card b { font-size: 34px; }
.note-list { margin: 0; padding-left: 18px; color: var(--muted); font-size: 13px; line-height: 1.45; }
.diag-shell { display:grid; gap: 14px; }
.diag-topline { display:grid; grid-template-columns: minmax(0, 1.6fr) repeat(3, minmax(150px, .55fr)); gap: 12px; }
.diag-hero {
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 18px 20px;
  background: linear-gradient(135deg, rgba(56,189,248,.12), rgba(15,23,42,.10));
}
.diag-hero-head { display:flex; align-items:center; justify-content:space-between; gap: 12px; }
.diag-kicker { color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.diag-state-pill {
  display:inline-flex; align-items:center; justify-content:center;
  padding: 6px 10px; border-radius: 999px; border: 1px solid var(--border);
  font-size: 11px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase;
}
.diag-state-pill.critical, .diag-state-pill.warning { color: #fca5a5; background: rgba(239,68,68,.12); }
.diag-state-pill.resolved { color: #86efac; background: rgba(34,197,94,.12); }
.diag-state-pill.stale { color: #fcd34d; background: rgba(245,158,11,.12); }
.diag-state-pill.healthy { color: #7dd3fc; background: rgba(56,189,248,.12); }
.diag-cause { margin-top: 8px; font-size: 28px; font-weight: 900; letter-spacing: -.04em; line-height: 1.05; max-width: 24ch; }
.diag-summary { margin-top: 10px; color: var(--muted); font-size: 15px; line-height: 1.5; max-width: 72ch; }
.diag-stat {
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 16px;
  background: var(--panel-2);
}
.diag-stat .label { color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.diag-stat .value { margin-top: 10px; font-size: 22px; font-weight: 900; letter-spacing: -.03em; line-height: 1.1; }
.diag-stat .mini { margin-top: 6px; color: var(--muted); font-size: 12px; line-height: 1.35; }
.diag-actions-row { display:flex; flex-wrap:wrap; gap: 10px; align-items:center; }
.diag-toggle {
  appearance:none; border: 1px solid var(--border); border-radius: 999px;
  background: var(--panel-2); color: var(--text); padding: 10px 14px;
  font-size: 12px; font-weight: 800; cursor: pointer;
}
.diag-toggle.active { background: rgba(56,189,248,.16); border-color: rgba(56,189,248,.40); }
.diag-grid { display:grid; grid-template-columns: minmax(0, 1.2fr) minmax(300px, .85fr); gap: 14px; }
.diag-list { display:grid; gap: 10px; }
.diag-item {
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 14px 15px;
  background: var(--panel-2);
}
.diag-item-head { display:flex; justify-content:space-between; gap: 10px; align-items:flex-start; }
.diag-item-label { font-size: 14px; font-weight: 800; }
.diag-item-value { margin-top: 7px; font-size: 15px; line-height: 1.5; }
.diag-item-hint { margin-top: 7px; color: var(--muted); font-size: 13px; line-height: 1.45; }
.diag-pill {
  display:inline-flex; align-items:center; justify-content:center;
  min-width: 72px; padding: 5px 10px; border-radius: 999px;
  border: 1px solid var(--border); font-size: 11px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase;
}
.diag-pill.high { color: #fca5a5; background: rgba(239,68,68,.14); }
.diag-pill.medium { color: #fbbf24; background: rgba(245,158,11,.14); }
.diag-pill.low { color: #7dd3fc; background: rgba(56,189,248,.14); }
.diag-sidebox {
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 14px;
  background: var(--panel-2);
}
.diag-sidebox h3 { margin: 0 0 8px; font-size: 16px; letter-spacing: -.02em; }
.diag-sidebox p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.45; }
.diag-sidebox .copyline { margin-top: 10px; color: var(--text); font-size: 14px; line-height: 1.45; }
.firewall-shell { display:grid; gap: 14px; }
.firewall-topline {
  display:grid;
  grid-template-columns: minmax(0, 1.25fr) repeat(4, minmax(140px, .45fr));
  gap: 12px;
}
.firewall-hero {
  border: 1px solid rgba(56,189,248,.24);
  border-radius: 20px;
  padding: 18px 20px;
  background:
    linear-gradient(135deg, rgba(56,189,248,.13), rgba(34,197,94,.08)),
    var(--panel-2);
}
.firewall-hero.attention, .firewall-hero.review {
  border-color: rgba(245,158,11,.34);
  background:
    linear-gradient(135deg, rgba(245,158,11,.14), rgba(56,189,248,.08)),
    var(--panel-2);
}
.firewall-hero.quiet {
  border-color: rgba(34,197,94,.30);
}
.firewall-kicker { color: var(--muted); font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; }
.firewall-title { margin-top: 8px; font-size: 30px; font-weight: 900; letter-spacing: -.04em; line-height: 1.05; }
.firewall-copy { margin-top: 10px; max-width: 74ch; color: var(--muted); font-size: 14px; line-height: 1.5; }
.firewall-stat {
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 15px;
  background: var(--panel-2);
}
.firewall-stat .label { color: var(--muted); font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; }
.firewall-stat .value { margin-top: 9px; font-size: 22px; font-weight: 900; letter-spacing: -.03em; line-height: 1.1; }
.firewall-stat .mini { margin-top: 6px; color: var(--muted); font-size: 12px; line-height: 1.35; }
.firewall-source-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.firewall-source-card {
  border: 1px solid var(--border);
  border-top: 4px solid #94a3b8;
  border-radius: 18px;
  padding: 15px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.035), transparent),
    var(--panel-2);
}
.firewall-source-card.cyan { border-top-color: #38bdf8; }
.firewall-source-card.green { border-top-color: #22c55e; }
.firewall-source-card.blue { border-top-color: #60a5fa; }
.firewall-source-card.amber { border-top-color: #f59e0b; }
.firewall-source-card.violet { border-top-color: #8b5cf6; }
.firewall-source-card.orange { border-top-color: #f97316; }
.firewall-source-card.slate { border-top-color: #94a3b8; }
.firewall-source-head { display:flex; justify-content:space-between; gap: 12px; align-items:flex-start; }
.firewall-device-name { font-size: 16px; font-weight: 900; line-height: 1.2; }
.firewall-ip { margin-top: 4px; color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.firewall-count { text-align:right; font-variant-numeric: tabular-nums; }
.firewall-count b { display:block; font-size: 24px; line-height: 1; }
.firewall-count span { display:block; margin-top: 4px; color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; }
.firewall-chiprow { display:flex; flex-wrap:wrap; gap: 6px; margin-top: 11px; }
.firewall-action {
  margin-top: 12px;
  border-left: 3px solid rgba(56,189,248,.5);
  padding-left: 10px;
  color: var(--text);
  font-size: 13px;
  line-height: 1.45;
}
.firewall-source-card.unmatched .firewall-action { border-left-color: rgba(245,158,11,.65); }
.empty { color: var(--muted); font-size: 14px; padding: 18px; border: 1px dashed var(--border); border-radius: 16px; }
.linkline { margin-top: auto; }
.linkline a { color: var(--accent); text-decoration: none; font-weight: 700; }
@media (max-width: 1180px) {
  .hero, .grid, .controls, .hero-grid, .score-grid, .diag-topline, .diag-grid, .chart-summary, .firewall-topline, .firewall-source-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <div class="hero-main panel">
      <h1>Pi Probe Interactive Dashboard</h1>
      <div class="sub" id="subtitle"></div>
      <div class="hero-meta">
        <div class="chip" id="dashboardVersion"></div>
        <div class="chip" id="dashboardFreshness"></div>
      </div>
      <div class="hero-grid">
        <div class="kpi"><div class="label">Median download</div><div class="value" id="kpiMedian"></div><div class="sub">Typical observed downstream performance</div><div class="sub" id="kpiMedianFreshness"></div></div>
        <div class="kpi"><div class="label">Average upload</div><div class="value" id="kpiUpload"></div><div class="sub">Mean upload across visible tests</div><div class="sub" id="kpiUploadFreshness"></div></div>
        <div class="kpi"><div class="label">Average ping</div><div class="value" id="kpiPing"></div><div class="sub">Mean latency across visible tests</div><div class="sub" id="kpiPingFreshness"></div></div>
        <div class="kpi"><div class="label">Reliability floor</div><div class="value" id="kpiFloor"></div><div class="sub">5th percentile download result</div><div class="sub" id="kpiFloorFreshness"></div></div>
      </div>
    </div>
    <div class="hero-side panel">
      <div class="verdict-badge" id="verdictBadge"></div>
      <div class="verdict" id="verdict"></div>
      <div class="copy" id="verdictCopy"></div>
      <div class="chiprow">
        <div class="chip" id="kpiThreshold"></div>
        <div class="chip" id="kpiFailed"></div>
        <div class="chip" id="kpiOutage"></div>
        <div class="chip" id="kpiDegraded"></div>
        <div class="chip" id="kpiStreak"></div>
      </div>
      <div class="copy" id="worstWindow"></div>
      <div class="linkline" id="dashboardLinkWrap"></div>
    </div>
  </section>

  <section class="controls">
    <div><label>Metric</label><select id="metric"><option value="download">Download Mbps</option><option value="upload">Upload Mbps</option><option value="ping">Ping ms</option></select></div>
    <div><label>Minimum speed threshold</label><input id="threshold" type="number" min="0" step="10"></div>
    <div><label>Day filter</label><select id="dayFilter"><option value="all">All days</option><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option><option>Saturday</option><option>Sunday</option></select></div>
    <div><label>Event severity</label><select id="severityFilter"></select></div>
    <div><label>Event type</label><select id="eventTypeFilter"></select></div>
    <div><label>Theme</label><select id="theme"><option value="auto">Auto / system</option><option value="premium">Premium dark</option><option value="clean">Clean light</option></select></div>
    <div id="apiTokenControl" style="display:none"><label>Action token</label><input id="apiToken" type="password" autocomplete="off" placeholder="Required"></div>
  </section>

  <section class="panel diag-section">
    <div class="panel-head"><div><h2>Network Fault Diagnosis</h2><p>Correlates router traps, device scan changes, and inventory freshness to highlight likely LAN-side failures.</p></div><div class="panel-stamp" id="diagnosisFreshness"></div></div>
    <div class="diag-shell">
      <div class="diag-topline">
        <div class="diag-hero">
          <div class="diag-hero-head">
            <div class="diag-kicker">Likely Cause</div>
            <div class="diag-state-pill" id="diagState"></div>
          </div>
          <div class="diag-cause" id="diagCause"></div>
          <div class="diag-summary" id="diagHeadline"></div>
        </div>
        <div class="diag-stat">
          <div class="label">Confidence</div>
          <div class="value" id="diagConfidence"></div>
          <div class="mini" id="diagConfidenceNote"></div>
        </div>
        <div class="diag-stat">
          <div class="label">Primary Suspect</div>
          <div class="value" id="diagSuspect"></div>
          <div class="mini" id="diagScanAge"></div>
        </div>
        <div class="diag-stat">
          <div class="label">Evidence</div>
          <div class="value" id="diagEvidenceSummary"></div>
          <div class="mini" id="diagLinkDown"></div>
        </div>
      </div>
      <div class="diag-actions-row">
        <button id="diagEvidenceToggle" class="diag-toggle active" type="button">Evidence</button>
        <button id="diagActionsToggle" class="diag-toggle" type="button">Next Actions</button>
        <button id="diagFocusEvents" class="diag-toggle" type="button">Focus Related Events</button>
        <button id="diagFocusExtender" class="diag-toggle" type="button">Show Suspect Device</button>
      </div>
      <div class="diag-grid">
        <div id="diagPrimaryList" class="diag-list"></div>
        <div class="diag-sidebox">
          <h3 id="diagSideTitle"></h3>
          <p id="diagSideIntro"></p>
          <div id="diagSideBody" class="copyline"></div>
        </div>
      </div>
    </div>
  </section>

  <section class="panel firewall-section">
    <div class="panel-head"><div><h2>Firewall Noise Sources</h2><p>Matches blocked firewall sources to scanned LAN devices so repeated noise has a name, hardware context, and next action.</p></div><div class="panel-stamp" id="firewallFreshness"></div></div>
    <div id="firewallShell" class="firewall-shell">
      <div class="firewall-topline">
        <div id="firewallHero" class="firewall-hero">
          <div class="firewall-kicker">Current Assessment</div>
          <div class="firewall-title" id="firewallSummary"></div>
          <div class="firewall-copy" id="firewallCopy"></div>
        </div>
        <div class="firewall-stat"><div class="label">Blocked</div><div class="value" id="firewallBlocked"></div><div class="mini" id="firewallBlockedMini"></div></div>
        <div class="firewall-stat"><div class="label">Noisy Sources</div><div class="value" id="firewallNoisySources"></div><div class="mini" id="firewallNoisyMini"></div></div>
        <div class="firewall-stat"><div class="label">SSH Attempts</div><div class="value" id="firewallSsh"></div><div class="mini" id="firewallPolicy"></div></div>
        <div class="firewall-stat"><div class="label">Top Port</div><div class="value" id="firewallTopPort"></div><div class="mini" id="firewallLogSource"></div></div>
      </div>
      <div id="firewallSources" class="firewall-source-grid"></div>
    </div>
    <div id="firewallEmpty" class="empty" style="display:none">Firewall data is not available for this dashboard yet.</div>
  </section>

  <section class="grid">
    <div class="stack">
      <div class="panel">
        <div class="panel-head"><div><h2>Performance Timeline</h2><p>Normal, degraded, outage, and failed tests are separated. Router event markers can be filtered by severity and type.</p></div><div class="panel-stamp" id="timelineFreshness"></div></div>
        <div id="timeline" class="chart"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><div><h2>Recent Router and Network Events</h2><p>Most recent 10 SNMP or imported overlay events available to the dashboard.</p></div><div class="panel-stamp" id="eventsFreshness"></div></div>
        <div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Message</th></tr></thead><tbody id="eventRows"></tbody></table></div>
      </div>
      <div class="panel">
        <div class="panel-head"><div><h2>Network Devices</h2><p>LAN inventory derived from the latest Nmap export. Devices are grouped by category for a quick visual sweep.</p></div><div class="panel-stamp" id="inventoryFreshness"></div></div>
        <div id="inventoryMeta" class="chart-meta"></div>
        <div class="action-row">
          <button id="nmapScanButton" class="action-button" type="button">Run Nmap Scan</button>
          <div id="nmapScanStatus" class="helper-text"></div>
        </div>
        <div id="deviceMap" class="device-map"></div>
        <div id="deviceMapEmpty" class="empty" style="display:none">No Nmap inventory data yet.</div>
      </div>
      <div class="panel">
        <div class="panel-head"><div><h2>Traffic-Light Heatmap</h2><p>Hourly average download. Green exceeds the good threshold, amber is acceptable, red is below target.</p></div><div class="panel-stamp" id="heatmapFreshness"></div></div>
        <div id="heatmapSummary" class="chart-summary"></div>
        <div id="heatmap" class="chart-small"></div>
        <div id="heatmapLegend" class="chart-meta"></div>
      </div>
    </div>
    <div class="stack">
      <div class="panel">
        <div class="panel-head"><div><h2>Latency Relationship</h2><p>Scatter of download versus ping. Failed, degraded, and outage tests are emphasised.</p></div><div class="panel-stamp" id="scatterFreshness"></div></div>
        <div id="scatter" class="chart-small"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><div><h2>DNS Activity Correlation</h2><p>Hourly DNS load and blocked requests plotted against average download when Pi-hole hourly data exists.</p></div><div class="panel-stamp" id="dnsFreshness"></div></div>
        <div id="dnsCorrelation" class="chart-small"></div>
        <div id="dnsLegend" class="chart-meta"></div>
        <div id="dnsEmpty" class="empty" style="display:none">No Pi-hole hourly data yet.</div>
      </div>
    </div>
  </section>
  <section class="panel score-section">
    <div class="panel-head"><div><h2>Connection Score</h2><p>One overall score plus four plain-English components so you can see what is actually dragging the connection down.</p></div><div class="panel-stamp" id="scoreFreshness"></div></div>
    <div class="score-grid">
      <div class="score-card"><div class="label">Download Strength</div><b id="scoreSpeed"></b><div class="mini" id="scoreSpeedNote"></div></div>
      <div class="score-card"><div class="label">Upload Consistency</div><b id="scoreUpload"></b><div class="mini" id="scoreUploadNote"></div></div>
      <div class="score-card"><div class="label">Latency</div><b id="scoreLatency"></b><div class="mini" id="scoreLatencyNote"></div></div>
      <div class="score-card"><div class="label">Reliability</div><b id="scoreStability"></b><div class="mini" id="scoreStabilityNote"></div></div>
    </div>
    <div class="score-card total-card" style="margin-bottom:12px"><div class="label">Overall Connection Score</div><b id="scoreTotal"></b><div class="mini" id="scoreSummary"></div></div>
    <ul class="note-list" id="scoreNotes"></ul>
  </section>
</div>
<script id="dashboard-payload" type="application/json">__PAYLOAD_JSON__</script>
<script>
const payload = JSON.parse(document.getElementById('dashboard-payload').textContent);
function sanitizePing(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return null;
  const ping = Number(value);
  if (ping < 0 || ping > 1000) return null;
  return ping;
}
function normalizeDashboardRows(rows) {
  return rows.map(row => ({
    ...row,
    ping: sanitizePing(row.ping)
  }));
}
const rawData = normalizeDashboardRows(payload.data);
const rawEvents = payload.events;
const piholeRows = payload.pihole;
const deviceRows = payload.devices;
const firewall = payload.firewall || {};
const inventory = payload.inventory;
const stats = payload.stats;
const score = payload.score;
const diagnosis = payload.diagnosis || {};
const thresholds = payload.thresholds;
const meta = payload.meta;
const refreshed = meta.refreshed || {};
const themeKey = 'pi_probe_dashboard_theme';
const actionTokenKey = 'pi_probe_dashboard_action_token';
let diagView = 'evidence';

function average(values) {
  const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v));
  return clean.length ? clean.reduce((a, b) => a + b, 0) / clean.length : 0;
}
function quantile(values, q) {
  const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v)).sort((a,b)=>a-b);
  if (!clean.length) return null;
  if (clean.length === 1) return clean[0];
  const pos = (clean.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  return clean[base + 1] !== undefined ? clean[base] + rest * (clean[base + 1] - clean[base]) : clean[base];
}
function getThemeChoice() { return localStorage.getItem(themeKey) || 'auto'; }
function resolveDarkMode(choice) {
  if (choice === 'premium') return true;
  if (choice === 'clean') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}
function applyTheme(choice) {
  localStorage.setItem(themeKey, choice);
  const dark = resolveDarkMode(choice);
  document.body.classList.toggle('theme-clean', !dark);
  render();
}
function svgEl(name, attrs = {}) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', name);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, String(value)));
  return el;
}
function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}
function setStatusClass(node, prefix, value) {
  Array.from(node.classList)
    .filter(name => name.startsWith(prefix))
    .forEach(name => node.classList.remove(name));
  node.classList.add(prefix + value);
}
function chartTheme() {
  const dark = !document.body.classList.contains('theme-clean');
  return {
    text: dark ? '#dbeafe' : '#0f172a',
    muted: dark ? '#94a3b8' : '#475569',
    grid: dark ? 'rgba(148,163,184,.12)' : 'rgba(15,23,42,.12)',
    border: dark ? 'rgba(148,163,184,.18)' : 'rgba(30,41,59,.18)',
    panel: dark ? '#07101c' : '#ffffff'
  };
}
function chartSurface(containerId, height) {
  const container = document.getElementById(containerId);
  clearNode(container);
  const width = Math.max(container.clientWidth || 720, 320);
  const svg = svgEl('svg', { viewBox: `0 0 ${width} ${height}`, width: '100%', height });
  container.appendChild(svg);
  return { container, svg, width, height, left: 58, right: 20, top: 18, bottom: 42 };
}
function extent(values, fallbackMax = 1) {
  const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v));
  if (!clean.length) return [0, fallbackMax];
  let min = Math.min(...clean);
  let max = Math.max(...clean);
  if (min === max) {
    const delta = min === 0 ? 1 : Math.abs(min) * 0.1;
    min -= delta;
    max += delta;
  }
  return [min, max];
}
function scaleLinear(domainMin, domainMax, rangeMin, rangeMax) {
  const span = domainMax - domainMin || 1;
  return value => rangeMin + ((value - domainMin) / span) * (rangeMax - rangeMin);
}
function makeTicks(min, max, count) {
  const ticks = [];
  const step = (max - min) / Math.max(count - 1, 1);
  for (let i = 0; i < count; i += 1) ticks.push(min + step * i);
  return ticks;
}
function drawAxes(surface, yMin, yMax, xLabels = []) {
  const { svg, width, height, left, right, top, bottom } = surface;
  const theme = chartTheme();
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const axis = svgEl('g');
  axis.appendChild(svgEl('line', { x1: left, y1: top + plotHeight, x2: width - right, y2: top + plotHeight, stroke: theme.border }));
  axis.appendChild(svgEl('line', { x1: left, y1: top, x2: left, y2: top + plotHeight, stroke: theme.border }));
  makeTicks(yMin, yMax, 5).forEach(value => {
    const y = top + plotHeight - ((value - yMin) / (yMax - yMin || 1)) * plotHeight;
    axis.appendChild(svgEl('line', { x1: left, y1: y, x2: width - right, y2: y, stroke: theme.grid }));
    const label = svgEl('text', { x: left - 8, y: y + 4, 'text-anchor': 'end', fill: theme.muted, 'font-size': 11 });
    label.textContent = Number.isInteger(value) ? `${Math.round(value)}` : value.toFixed(1);
    axis.appendChild(label);
  });
  xLabels.forEach(({ x, label }) => {
    axis.appendChild(svgEl('line', { x1: x, y1: top + plotHeight, x2: x, y2: top + plotHeight + 4, stroke: theme.border }));
    const text = svgEl('text', { x, y: height - 12, 'text-anchor': 'middle', fill: theme.muted, 'font-size': 11 });
    text.textContent = label;
    axis.appendChild(text);
  });
  svg.appendChild(axis);
}
function drawRightAxis(surface, yMin, yMax, formatter) {
  const { svg, width, top, right, bottom, height } = surface;
  const theme = chartTheme();
  const plotHeight = height - top - bottom;
  const axis = svgEl('g');
  const x = width - right;
  axis.appendChild(svgEl('line', { x1: x, y1: top, x2: x, y2: top + plotHeight, stroke: theme.border }));
  makeTicks(yMin, yMax, 5).forEach(value => {
    const y = top + plotHeight - ((value - yMin) / (yMax - yMin || 1)) * plotHeight;
    axis.appendChild(svgEl('line', { x1: x - 4, y1: y, x2: x, y2: y, stroke: theme.border }));
    const label = svgEl('text', { x: x + 8, y: y + 4, fill: theme.muted, 'font-size': 11 });
    label.textContent = formatter(value);
    axis.appendChild(label);
  });
  svg.appendChild(axis);
}
function pathFromPoints(points) {
  if (!points.length) return '';
  return points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point[0].toFixed(2)} ${point[1].toFixed(2)}`).join(' ');
}
function setText(elementId, value) {
  document.getElementById(elementId).textContent = value;
}
function getActionHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (inventory.apiTokenRequired) {
    const token = (document.getElementById('apiToken')?.value || localStorage.getItem(actionTokenKey) || '').trim();
    if (token) headers['X-Pi-Probe-Token'] = token;
  }
  return headers;
}
function actionAuthReady() {
  return !inventory.apiTokenRequired || Boolean((document.getElementById('apiToken')?.value || '').trim());
}
function initActionTokenControl() {
  const wrap = document.getElementById('apiTokenControl');
  const input = document.getElementById('apiToken');
  if (!wrap || !input) return;
  wrap.style.display = inventory.apiTokenRequired ? 'block' : 'none';
  input.value = localStorage.getItem(actionTokenKey) || '';
  input.addEventListener('input', () => {
    localStorage.setItem(actionTokenKey, input.value.trim());
    renderInventoryMeta();
    renderDeviceMap();
  });
}
function formatFreshness(value) {
  if (!value) return 'Refresh unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Refresh unknown';
  const diffMs = Date.now() - date.getTime();
  const diffMinutes = Math.max(0, Math.floor(diffMs / 60000));
  let relative = 'just now';
  if (diffMinutes >= 60 * 24) {
    const days = Math.floor(diffMinutes / (60 * 24));
    const hours = Math.floor((diffMinutes % (60 * 24)) / 60);
    relative = hours ? `${days}d ${hours}h ago` : `${days}d ago`;
  } else if (diffMinutes >= 60) {
    const hours = Math.floor(diffMinutes / 60);
    const minutes = diffMinutes % 60;
    relative = minutes ? `${hours}h ${minutes}m ago` : `${hours}h ago`;
  } else if (diffMinutes > 0) {
    relative = `${diffMinutes}m ago`;
  }
  return `${relative} · ${date.toLocaleString()}`;
}
function relativeFreshness(value) {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  const diffMinutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
  if (diffMinutes < 1) return 'just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  const hours = Math.floor(diffMinutes / 60);
  const minutes = diffMinutes % 60;
  if (hours < 24) return minutes ? `${hours}h ${minutes}m ago` : `${hours}h ago`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days}d ${remHours}h ago` : `${days}d ago`;
}
function freshnessClass(value) {
  if (!value) return 'stale';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'stale';
  const diffMinutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
  if (diffMinutes <= 30) return 'fresh';
  if (diffMinutes <= 180) return 'aging';
  return 'stale';
}
function setFreshness(elementId, value, prefix = 'Updated') {
  const node = document.getElementById(elementId);
  if (!node) return;
  node.textContent = `${prefix} ${formatFreshness(value)}`;
}
function renderFreshness() {
  setText('dashboardVersion', `Version ${meta.version || 'unknown'}`);
  setFreshness('dashboardFreshness', refreshed.dashboard || meta.generated_at, 'Built');
  ['kpiMedianFreshness', 'kpiUploadFreshness', 'kpiPingFreshness', 'kpiFloorFreshness'].forEach(id => {
    setFreshness(id, refreshed.speed, 'Data');
  });
  setFreshness('timelineFreshness', refreshed.speed, 'Data');
  setFreshness('diagnosisFreshness', refreshed.diagnosis, 'Data');
  setFreshness('firewallFreshness', refreshed.dashboard || meta.generated_at, 'Built');
  setFreshness('eventsFreshness', refreshed.events, 'Data');
  setFreshness('inventoryFreshness', refreshed.inventory, 'Scan');
  setFreshness('heatmapFreshness', refreshed.speed, 'Data');
  setFreshness('scatterFreshness', refreshed.speed, 'Data');
  setFreshness('dnsFreshness', refreshed.pihole, 'Data');
  setFreshness('scoreFreshness', refreshed.speed, 'Data');
}
function initFilters() {
  const severitySelect = document.getElementById('severityFilter');
  const typeSelect = document.getElementById('eventTypeFilter');
  const severities = ['all', ...new Set(rawEvents.map(e => e.severity || 'info'))];
  const types = ['all', ...new Set(rawEvents.map(e => e.eventType || 'event'))];
  [severitySelect, typeSelect].forEach(select => clearNode(select));
  severities.forEach(value => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value === 'all' ? 'All severities' : value;
    severitySelect.appendChild(option);
  });
  types.forEach(value => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value === 'all' ? 'All types' : value;
    typeSelect.appendChild(option);
  });
}
function filteredData() {
  const day = document.getElementById('dayFilter').value;
  return rawData.filter(item => day === 'all' || item.day === day);
}
function filteredEvents() {
  const severity = document.getElementById('severityFilter').value;
  const eventType = document.getElementById('eventTypeFilter').value;
  return rawEvents.filter(item => (severity === 'all' || item.severity === severity) && (eventType === 'all' || item.eventType === eventType));
}
function renderTable(events) {
  const body = document.getElementById('eventRows');
  clearNode(body);
  if (!events.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.className = 'table-empty';
    cell.textContent = 'No matching events.';
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  events.slice(-10).reverse().forEach(event => {
    const row = document.createElement('tr');
    const timeCell = document.createElement('td');
    timeCell.className = 'time-cell';
    timeCell.textContent = event.time;
    row.appendChild(timeCell);

    const typeCell = document.createElement('td');
    typeCell.className = 'type-cell';
    typeCell.textContent = event.eventType;
    row.appendChild(typeCell);

    const severityCell = document.createElement('td');
    const severityPill = document.createElement('span');
    severityPill.className = `severity-pill ${event.severity || 'info'}`;
    severityPill.textContent = event.severity || 'info';
    severityCell.appendChild(severityPill);
    row.appendChild(severityCell);

    const sourceCell = document.createElement('td');
    sourceCell.className = 'source-cell';
    sourceCell.textContent = event.source || 'n/a';
    row.appendChild(sourceCell);

    const messageCell = document.createElement('td');
    messageCell.className = 'message-cell';
    messageCell.textContent = event.message || '';
    row.appendChild(messageCell);
    body.appendChild(row);
  });
}
function renderInventoryMeta() {
  const metaWrap = document.getElementById('inventoryMeta');
  const status = document.getElementById('nmapScanStatus');
  const button = document.getElementById('nmapScanButton');
  clearNode(metaWrap);
  const items = [];
  if (inventory.scannedAt) items.push(`Scanned ${new Date(inventory.scannedAt).toLocaleString()}`);
  if (inventory.network) items.push(`Network ${inventory.network}`);
  items.push(`${inventory.deviceCount || 0} discovered`);
  if (inventory.scanTargets) items.push(`Targets ${inventory.scanTargets}`);
  if (inventory.scanMinutes) items.push(`Schedule ${inventory.scanMinutes} min`);
  items.forEach(label => {
    const chip = document.createElement('div');
    chip.className = 'legend-chip';
    chip.textContent = label;
    metaWrap.appendChild(chip);
  });
  button.disabled = !(window.location.protocol.startsWith('http') && inventory.actionsEnabled && actionAuthReady());
  if (!window.location.protocol.startsWith('http')) {
    status.textContent = 'Serve the dashboard to enable Nmap scan actions.';
  } else if (inventory.actionMode === 'locked') {
    status.textContent = 'Dashboard actions are locked until PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN is configured.';
  } else if (inventory.apiTokenRequired && !actionAuthReady()) {
    status.textContent = 'Enter the action token to enable scan and device actions.';
  } else if (!inventory.actionsEnabled) {
    status.textContent = inventory.scanArguments ? `Configured scan: nmap ${inventory.scanArguments} ${inventory.scanTargets}` : 'Nmap scan actions are unavailable for this dashboard.';
  } else if (!status.textContent) {
    status.textContent = inventory.scanArguments ? `Configured scan: nmap ${inventory.scanArguments} ${inventory.scanTargets}` : 'Run a fresh scan to update the device inventory.';
  }
}
function renderDiagnosis() {
  const stateNode = document.getElementById('diagState');
  setText('diagCause', diagnosis.likelyCause || diagnosis.headline || 'No diagnosis summary available.');
  setText('diagHeadline', diagnosis.headline || 'No diagnosis summary available.');
  setText('diagConfidence', diagnosis.confidenceLabel || 'Unknown');
  setText('diagConfidenceNote', `Current ${diagnosis.decisionWindowHours || 8}h: ${diagnosis.hostMissingCount || 0} missing-host, ${diagnosis.portClosedCount || 0} port-change, ${diagnosis.restartCount || 0} restart`);
  setText('diagSuspect', diagnosis.primarySuspect || 'Unknown');
  setText('diagScanAge', `Inventory ${diagnosis.scanAge || 'unknown'}${diagnosis.inventoryFresh ? '' : ' · stale'}`);
  setText('diagEvidenceSummary', `${diagnosis.inventoryDeviceCount || 0} visible / ${diagnosis.infrastructureCount || 0} infra`);
  setText('diagLinkDown', `${diagnosis.linkDownCount || 0} linkDown now · context ${diagnosis.historicalFaultCount || 0} event(s), last ${diagnosis.latestContextFaultAge || diagnosis.latestFaultAge || 'unknown'}`);
  stateNode.textContent = diagnosis.statusLabel || 'Resolved';
  stateNode.className = `diag-state-pill ${diagnosis.status || 'healthy'}`;

  const list = document.getElementById('diagPrimaryList');
  clearNode(list);
  const sideTitle = document.getElementById('diagSideTitle');
  const sideIntro = document.getElementById('diagSideIntro');
  const sideBody = document.getElementById('diagSideBody');
  clearNode(sideBody);

  const evidenceItems = diagnosis.evidenceItems || [];
  const actionItems = diagnosis.recommendations || [];
  const showingEvidence = diagView === 'evidence';
  const items = showingEvidence
    ? evidenceItems
    : actionItems.map(item => ({ label: 'Action', value: item, hint: 'Use this on the next recurrence or after restoring connectivity.' }));

  sideTitle.textContent = showingEvidence ? 'What This Is Using' : 'How To Use This';
  sideIntro.textContent = showingEvidence
    ? 'These are the strongest pieces of telemetry currently driving the diagnosis.'
    : 'Keep the response short and decisive when the fault happens again.';
  sideBody.textContent = showingEvidence
    ? `${diagnosis.statusLabel || 'Resolved'}. Confidence: ${diagnosis.confidenceLabel || 'Unknown'}. Primary suspect: ${diagnosis.primarySuspect || 'Unknown'}. Current evidence window: ${diagnosis.decisionWindowHours || 8}h.`
    : 'Start with a fresh scan, then compare the suspect device MAC, IP, and open ports before rebooting anything.';

  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'diag-item';
    empty.textContent = showingEvidence ? 'No evidence items available yet.' : 'No action items available yet.';
    list.appendChild(empty);
  } else {
    items.forEach((item, index) => {
      const card = document.createElement('article');
      card.className = 'diag-item';
      const head = document.createElement('div');
      head.className = 'diag-item-head';
      const label = document.createElement('div');
      label.className = 'diag-item-label';
      label.textContent = item.label || `Item ${index + 1}`;
      head.appendChild(label);
      if (showingEvidence && index === 0) {
        const pill = document.createElement('span');
        pill.className = `diag-pill ${diagnosis.confidence || 'low'}`;
        pill.textContent = diagnosis.confidenceLabel || 'Signal';
        head.appendChild(pill);
      }
      card.appendChild(head);
      const value = document.createElement('div');
      value.className = 'diag-item-value';
      value.textContent = item.value || '';
      card.appendChild(value);
      if (item.hint) {
        const hint = document.createElement('div');
        hint.className = 'diag-item-hint';
        hint.textContent = item.hint;
        card.appendChild(hint);
      }
      list.appendChild(card);
    });
  }

  document.getElementById('diagEvidenceToggle').classList.toggle('active', showingEvidence);
  document.getElementById('diagActionsToggle').classList.toggle('active', !showingEvidence);
}
function focusDiagnosisEvents() {
  const typeFilter = document.getElementById('eventTypeFilter');
  const preferred = ['host_missing', 'port_closed', 'SNMPv2-MIB::warmStart', 'SNMPv2-MIB::coldStart'];
  const optionValues = Array.from(typeFilter.options).map(option => option.value);
  const match = preferred.find(value => optionValues.includes(value));
  if (match) typeFilter.value = match;
  document.getElementById('severityFilter').value = 'all';
  render();
  document.getElementById('eventRows').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function focusSuspectDevice() {
  const suspect = (diagnosis.primarySuspect || '').toLowerCase();
  if (!suspect) return;
  const cards = Array.from(document.querySelectorAll('.device-card'));
  cards.forEach(card => {
    const text = card.textContent.toLowerCase();
    card.style.outline = text.includes(suspect) ? '2px solid rgba(56,189,248,.65)' : 'none';
    card.style.outlineOffset = text.includes(suspect) ? '2px' : '0';
  });
  const match = cards.find(card => card.textContent.toLowerCase().includes(suspect));
  if (match) match.scrollIntoView({ behavior: 'smooth', block: 'center' });
}
function renderFirewallNoise() {
  const shell = document.getElementById('firewallShell');
  const empty = document.getElementById('firewallEmpty');
  const sourceWrap = document.getElementById('firewallSources');
  clearNode(sourceWrap);
  if (!firewall.available) {
    shell.style.display = 'none';
    empty.style.display = 'block';
    empty.textContent = firewall.error ? `Firewall data unavailable: ${firewall.error}` : 'Firewall data is not available for this dashboard yet.';
    return;
  }

  shell.style.display = 'grid';
  empty.style.display = 'none';
  const hero = document.getElementById('firewallHero');
  hero.className = `firewall-hero ${firewall.tone || 'contained'}`;
  setText('firewallSummary', firewall.summary || 'Firewall activity summary unavailable');
  setText('firewallCopy', (firewall.notes || [])[0] || 'Blocked traffic is being correlated against the latest device inventory.');
  setText('firewallBlocked', String(firewall.blocked || 0));
  setText('firewallBlockedMini', `${firewall.windowHours || 24}h window - ${firewall.totalEntries || 0} entries reviewed`);
  setText('firewallNoisySources', String(firewall.noisySources || 0));
  setText('firewallNoisyMini', `${(firewall.sources || []).length} source${(firewall.sources || []).length === 1 ? '' : 's'} shown`);
  setText('firewallSsh', String(firewall.sshAttempts || 0));
  setText('firewallPolicy', firewall.policy || 'Policy unknown');
  const topPort = (firewall.ports || [])[0];
  setText('firewallTopPort', topPort ? topPort.port : 'n/a');
  setText('firewallLogSource', firewall.logError || `Log ${firewall.logSource || 'unknown'}`);

  const sources = firewall.sources || [];
  if (!sources.length) {
    const emptyCard = document.createElement('div');
    emptyCard.className = 'empty';
    emptyCard.textContent = 'No noisy source devices in the current firewall window.';
    sourceWrap.appendChild(emptyCard);
    return;
  }

  sources.forEach(source => {
    const device = source.device || {};
    const card = document.createElement('article');
    card.className = `firewall-source-card ${device.accent || 'slate'}${source.matched ? '' : ' unmatched'}`;
    const head = document.createElement('div');
    head.className = 'firewall-source-head';
    const identity = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'firewall-device-name';
    name.textContent = source.matched ? (device.name || device.hostname || source.ip) : 'Unknown LAN device';
    const ip = document.createElement('div');
    ip.className = 'firewall-ip';
    ip.textContent = source.ip || 'n/a';
    identity.appendChild(name);
    identity.appendChild(ip);
    const count = document.createElement('div');
    count.className = 'firewall-count';
    const countValue = document.createElement('b');
    countValue.textContent = source.count || 0;
    const countLabel = document.createElement('span');
    countLabel.textContent = `${source.share || 0}% of noise`;
    count.appendChild(countValue);
    count.appendChild(countLabel);
    head.appendChild(identity);
    head.appendChild(count);
    card.appendChild(head);

    const chips = document.createElement('div');
    chips.className = 'firewall-chiprow';
    [
      source.risk,
      source.scope,
      device.categoryLabel,
      device.vendor || 'Unknown vendor',
      device.mac ? `MAC ${device.mac}` : '',
      device.lastSeen ? `Seen ${relativeFreshness(device.lastSeen)}` : '',
    ].filter(Boolean).forEach(label => {
      const chip = document.createElement('span');
      chip.className = 'device-chip';
      chip.textContent = label;
      chips.appendChild(chip);
    });
    (device.services || []).slice(0, 3).forEach(service => {
      const chip = document.createElement('span');
      chip.className = 'device-chip primary';
      chip.textContent = service;
      chips.appendChild(chip);
    });
    if (!(device.services || []).length && (device.openPorts || []).length) {
      const chip = document.createElement('span');
      chip.className = 'device-chip primary';
      chip.textContent = `Ports ${(device.openPorts || []).slice(0, 4).join(', ')}`;
      chips.appendChild(chip);
    }
    card.appendChild(chips);

    const action = document.createElement('div');
    action.className = 'firewall-action';
    action.textContent = source.action || 'Review this source before suppressing future alerts.';
    card.appendChild(action);
    sourceWrap.appendChild(card);
  });
}
function renderDeviceMap() {
  const map = document.getElementById('deviceMap');
  const empty = document.getElementById('deviceMapEmpty');
  clearNode(map);
  if (!deviceRows.length) {
    map.style.display = 'none';
    empty.style.display = 'block';
    return;
  }
  map.style.display = 'grid';
  empty.style.display = 'none';
  const order = ['Infrastructure', 'Servers', 'Computers', 'Mobile', 'Media', 'IoT', 'Unknown'];
  order.forEach(categoryLabel => {
    const rows = deviceRows.filter(item => item.categoryLabel === categoryLabel);
    if (!rows.length) return;
    const cluster = document.createElement('section');
    cluster.className = 'device-cluster';
    const head = document.createElement('div');
    head.className = 'cluster-head';
    const title = document.createElement('div');
    title.className = 'cluster-title';
    title.textContent = categoryLabel;
    const count = document.createElement('div');
    count.className = 'cluster-count';
    count.textContent = `${rows.length} device${rows.length === 1 ? '' : 's'}`;
    head.appendChild(title);
    head.appendChild(count);
    cluster.appendChild(head);
    const list = document.createElement('div');
    list.className = 'device-list';
    rows.forEach(device => {
      const card = document.createElement('article');
      card.className = `device-card ${device.accent || 'slate'}`;
      const name = document.createElement('div');
      name.className = 'device-name';
      name.textContent = device.name || device.hostname || device.ip || 'Unknown device';
      const ip = document.createElement('div');
      ip.className = 'device-ip';
      ip.textContent = device.ip || device.hostname || 'n/a';
      const meta = document.createElement('div');
      meta.className = 'device-meta';
      const vendor = document.createElement('span');
      vendor.className = 'device-chip';
      vendor.textContent = device.vendor || 'Unknown vendor';
      meta.appendChild(vendor);
      if (device.mac) {
        const mac = document.createElement('span');
        mac.className = 'device-chip';
        mac.textContent = `MAC ${device.mac}`;
        meta.appendChild(mac);
      }
      if (device.lastSeen) {
        const seen = document.createElement('span');
        seen.className = `device-chip ${freshnessClass(device.lastSeen)}`;
        seen.textContent = `Seen ${relativeFreshness(device.lastSeen)}`;
        meta.appendChild(seen);
      }
      const portCount = document.createElement('span');
      portCount.className = 'device-chip primary';
      portCount.textContent = `${device.portCount || 0} open port${(device.portCount || 0) === 1 ? '' : 's'}`;
      meta.appendChild(portCount);
      const services = document.createElement('div');
      services.className = 'device-services';
      (device.services || []).slice(0, 4).forEach(service => {
        const chip = document.createElement('span');
        chip.className = 'device-chip';
        chip.textContent = service;
        services.appendChild(chip);
      });
      if (!services.childNodes.length && Array.isArray(device.openPorts) && device.openPorts.length) {
        const chip = document.createElement('span');
        chip.className = 'device-chip';
        chip.textContent = `Ports ${device.openPorts.slice(0, 4).join(', ')}`;
        services.appendChild(chip);
      }
      card.appendChild(name);
      card.appendChild(ip);
      card.appendChild(meta);
      if (services.childNodes.length) card.appendChild(services);
      card.appendChild(buildDeviceEditor(device));
      list.appendChild(card);
    });
    cluster.appendChild(list);
    map.appendChild(cluster);
  });
}
function buildDeviceEditor(device) {
  const editor = document.createElement('form');
  editor.className = 'device-editor';

  const nameWrap = document.createElement('div');
  const nameLabel = document.createElement('label');
  nameLabel.textContent = 'Display name';
  const nameInput = document.createElement('input');
  nameInput.type = 'text';
  nameInput.value = device.name || '';
  nameWrap.appendChild(nameLabel);
  nameWrap.appendChild(nameInput);

  const categoryWrap = document.createElement('div');
  const categoryLabel = document.createElement('label');
  categoryLabel.textContent = 'Category';
  const categorySelect = document.createElement('select');
  const categories = [
    ['infrastructure', 'Infrastructure'],
    ['servers', 'Servers'],
    ['computers', 'Computers'],
    ['mobile', 'Mobile'],
    ['media', 'Media'],
    ['iot', 'IoT'],
    ['unknown', 'Unknown'],
  ];
  categories.forEach(([value, label]) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    option.selected = device.category === value;
    categorySelect.appendChild(option);
  });
  categoryWrap.appendChild(categoryLabel);
  categoryWrap.appendChild(categorySelect);

  const status = document.createElement('div');
  status.className = 'device-status';
  status.textContent = device.hostname ? `Host ${device.hostname}` : 'Edit override';

  const actions = document.createElement('div');
  actions.className = 'device-actions';
  const save = document.createElement('button');
  save.type = 'submit';
  save.className = 'mini-button primary';
  save.textContent = 'Save';
  const clear = document.createElement('button');
  clear.type = 'button';
  clear.className = 'mini-button warn';
  clear.textContent = 'Clear override';
  actions.appendChild(save);
  actions.appendChild(clear);

  const tools = document.createElement('div');
  tools.className = 'device-tool-row';
  const ping = document.createElement('button');
  ping.type = 'button';
  ping.className = 'mini-button';
  ping.textContent = 'Ping';
  tools.appendChild(ping);

  editor.appendChild(nameWrap);
  editor.appendChild(categoryWrap);
  editor.appendChild(tools);
  editor.appendChild(actions);
  editor.appendChild(status);

  const actionsReady = inventory.actionsEnabled && actionAuthReady();
  save.disabled = !actionsReady;
  clear.disabled = !actionsReady;
  if (!actionsReady) {
    nameInput.disabled = true;
    categorySelect.disabled = true;
  }

  editor.addEventListener('submit', async event => {
    event.preventDefault();
    save.disabled = true;
    clear.disabled = true;
    status.textContent = 'Saving device override...';
    const response = await submitDeviceOverride(device, {
      action: 'set',
      name: nameInput.value.trim(),
      category: categorySelect.value,
    });
    status.textContent = response.message;
    if (response.ok) window.location.reload();
    save.disabled = false;
    clear.disabled = false;
  });

  clear.addEventListener('click', async () => {
    save.disabled = true;
    clear.disabled = true;
    status.textContent = 'Clearing device override...';
    const response = await submitDeviceOverride(device, { action: 'clear' });
    status.textContent = response.message;
    if (response.ok) window.location.reload();
    save.disabled = false;
    clear.disabled = false;
  });

  ping.addEventListener('click', async () => {
    ping.disabled = true;
    status.textContent = `Pinging ${device.ip || device.hostname || device.name || 'device'}...`;
    const response = await pingDashboardDevice(device);
    status.textContent = response.message;
    ping.disabled = false;
  });

  if (!actionsReady) {
    status.textContent = inventory.apiTokenRequired ? 'Enter action token to edit or ping.' : 'Actions unavailable';
  }

  return editor;
}
async function pingDashboardDevice(device) {
  try {
    const response = await fetch('/api/device/ping', {
      method: 'POST',
      headers: getActionHeaders(),
      body: JSON.stringify({
        ip: device.ip || '',
        hostname: device.hostname || '',
        name: device.name || '',
      }),
    });
    const result = await response.json();
    return {
      ok: Boolean(response.ok && result.ok),
      message: result.message || 'Ping request completed.',
    };
  } catch (error) {
    return {
      ok: false,
      message: `Ping failed: ${error instanceof Error ? error.message : 'request error'}`,
    };
  }
}
async function submitDeviceOverride(device, changes) {
  const selector = device.mac
    ? { mac: device.mac }
    : device.ip
      ? { ip: device.ip }
      : device.hostname
        ? { hostname: device.hostname }
        : {};
  try {
    const response = await fetch('/api/nmap/override', {
      method: 'POST',
      headers: getActionHeaders(),
      body: JSON.stringify({
        selector,
        ...changes,
      }),
    });
    const result = await response.json();
    return {
      ok: Boolean(response.ok && result.ok),
      message: result.message || 'Override request completed.',
    };
  } catch (error) {
    return {
      ok: false,
      message: `Override failed: ${error instanceof Error ? error.message : 'request error'}`,
    };
  }
}
async function triggerNmapScan() {
  const button = document.getElementById('nmapScanButton');
  const status = document.getElementById('nmapScanStatus');
  if (button.disabled) return;
  button.disabled = true;
  status.textContent = 'Running Nmap scan and refreshing dashboard...';
  try {
    const response = await fetch('/api/nmap/scan', { method: 'POST', headers: getActionHeaders() });
    const result = await response.json();
    status.textContent = result.message || 'Nmap scan finished.';
    if (!response.ok || !result.ok) {
      button.disabled = false;
      return;
    }
    window.location.reload();
  } catch (error) {
    status.textContent = `Nmap scan failed: ${error instanceof Error ? error.message : 'request error'}`;
    button.disabled = false;
  }
}
function heatmapColor(value, maxValue) {
  if (value === null || value === undefined) return 'rgba(148,163,184,.20)';
  if (value >= thresholds.heatmapGoodMbps) return '#15803d';
  if (value >= thresholds.heatmapWarnMbps) return '#f59e0b';
  return value >= thresholds.outageDownloadMbps ? '#ef4444' : '#b91c1c';
}
function heatmapBand(value) {
  if (value === null || value === undefined) return 'No data';
  if (value >= thresholds.heatmapGoodMbps) return 'Strong';
  if (value >= thresholds.heatmapWarnMbps) return 'Acceptable';
  if (value >= thresholds.outageDownloadMbps) return 'Weak';
  return 'Severely weak';
}
function renderHeatmapLegend(summary) {
  const wrap = document.getElementById('heatmapLegend');
  clearNode(wrap);
  [
    { color: '#15803d', label: `Strong ≥ ${thresholds.heatmapGoodMbps.toFixed(0)} Mbps` },
    { color: '#f59e0b', label: `Acceptable ${thresholds.heatmapWarnMbps.toFixed(0)}-${(thresholds.heatmapGoodMbps - 0.1).toFixed(0)} Mbps` },
    { color: '#ef4444', label: `Weak ${thresholds.outageDownloadMbps.toFixed(0)}-${(thresholds.heatmapWarnMbps - 0.1).toFixed(0)} Mbps` },
    { color: '#b91c1c', label: `Severely weak < ${thresholds.outageDownloadMbps.toFixed(0)} Mbps` },
    { color: 'rgba(148,163,184,.35)', label: `${summary.coverage}% hourly cells have data` },
  ].forEach(item => {
    const chip = document.createElement('div');
    chip.className = 'legend-chip';
    const swatch = document.createElement('span');
    swatch.className = 'legend-swatch';
    swatch.style.background = item.color;
    chip.appendChild(swatch);
    chip.appendChild(document.createTextNode(item.label));
    wrap.appendChild(chip);
  });
}
function renderHeatmapSummary(summary) {
  const wrap = document.getElementById('heatmapSummary');
  clearNode(wrap);
  [
    {
      label: 'Best Window',
      value: summary.bestLabel,
      note: summary.bestValue === null ? 'No strong period identified yet.' : `${summary.bestValue.toFixed(0)} Mbps average download`,
    },
    {
      label: 'Weakest Window',
      value: summary.worstLabel,
      note: summary.worstValue === null ? 'No weak period identified yet.' : `${summary.worstValue.toFixed(0)} Mbps average download`,
    },
    {
      label: 'Reading',
      value: summary.takeaway,
      note: `${summary.goodCells} strong, ${summary.warnCells} acceptable, ${summary.badCells + summary.severeCells} weak cells`,
    },
  ].forEach(item => {
    const card = document.createElement('div');
    card.className = 'summary-card';
    const label = document.createElement('div');
    label.className = 'label';
    label.textContent = item.label;
    const value = document.createElement('div');
    value.className = 'value';
    value.textContent = item.value;
    const note = document.createElement('div');
    note.className = 'mini';
    note.textContent = item.note;
    card.appendChild(label);
    card.appendChild(value);
    card.appendChild(note);
    wrap.appendChild(card);
  });
}
function renderTimeline(data, events) {
  const metric = document.getElementById('metric').value;
  const surface = chartSurface('timeline', 390);
  const theme = chartTheme();
  const plotWidth = surface.width - surface.left - surface.right;
  const plotHeight = surface.height - surface.top - surface.bottom;
  const points = data.filter(item => item[metric] !== null).map(item => ({ ...item, ts: new Date(item.datetime).getTime() }));
  if (!points.length) return;
  const [xMin, xMax] = extent(points.map(item => item.ts), points[0].ts + 1);
  const [yMin0, yMax0] = extent(points.map(item => Number(item[metric])), 1);
  const yMin = metric === 'ping' ? Math.max(0, yMin0 * 0.95) : Math.max(0, yMin0 * 0.9);
  const yMax = yMax0 * 1.05;
  const scaleX = scaleLinear(xMin, xMax, surface.left, surface.left + plotWidth);
  const scaleY = scaleLinear(yMin, yMax, surface.top + plotHeight, surface.top);
  const xTicks = makeTicks(xMin, xMax, Math.min(6, points.length)).map(value => ({
    x: scaleX(value),
    label: new Date(value).toLocaleDateString(undefined, { day: '2-digit', month: 'short' })
  }));
  drawAxes(surface, yMin, yMax, xTicks);
  const eventLines = svgEl('g');
  events.forEach(event => {
    const x = scaleX(new Date(event.datetime).getTime());
    eventLines.appendChild(svgEl('line', {
      x1: x, y1: surface.top, x2: x, y2: surface.top + plotHeight,
      stroke: event.severity === 'critical' ? '#ef4444' : event.severity === 'warning' ? '#f59e0b' : '#94a3b8',
      'stroke-dasharray': '4 4'
    }));
  });
  surface.svg.appendChild(eventLines);
  const line = svgEl('path', {
    d: pathFromPoints(points.map(item => [scaleX(item.ts), scaleY(Number(item[metric]))])),
    fill: 'none',
    stroke: '#38bdf8',
    'stroke-width': 2.4
  });
  surface.svg.appendChild(line);
  points.forEach(item => {
    const circle = svgEl('circle', {
      cx: scaleX(item.ts),
      cy: scaleY(Number(item[metric])),
      r: item.status === 'failed' ? 4.5 : 3.5,
      fill: item.status === 'degraded' ? '#f59e0b' : item.status === 'outage' ? '#ef4444' : item.status === 'failed' ? '#f97316' : '#38bdf8'
    });
    const title = svgEl('title');
    title.textContent = `${item.label} • ${metric}: ${Number(item[metric]).toFixed(2)} • ${item.status}`;
    circle.appendChild(title);
    surface.svg.appendChild(circle);
  });
  const yLabel = svgEl('text', { x: 18, y: surface.top + plotHeight / 2, fill: theme.muted, 'font-size': 11, transform: `rotate(-90 18 ${surface.top + plotHeight / 2})` });
  yLabel.textContent = metric === 'ping' ? 'Milliseconds' : 'Mbps';
  surface.svg.appendChild(yLabel);
}
function renderHeatmap(data) {
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  const surface = chartSurface('heatmap', 320);
  const maxValue = Math.max(thresholds.heatmapGoodMbps * 1.15, ...rawData.map(item => item.download || 0), thresholds.heatmapWarnMbps + 1);
  const cellWidth = (surface.width - surface.left - surface.right) / 24;
  const cellHeight = (surface.height - surface.top - surface.bottom) / 7;
  const hourlyCells = [];
  days.forEach((day, rowIndex) => {
    const label = svgEl('text', { x: surface.left - 10, y: surface.top + rowIndex * cellHeight + cellHeight / 2 + 4, 'text-anchor': 'end', fill: chartTheme().muted, 'font-size': 11 });
    label.textContent = day.slice(0, 3);
    surface.svg.appendChild(label);
    Array.from({ length: 24 }, (_, hour) => hour).forEach(hour => {
      const values = data.filter(item => item.day === day && item.hour === hour).map(item => item.download).filter(v => v !== null);
      const avgValue = values.length ? average(values) : null;
      hourlyCells.push({ day, hour, avgValue, band: heatmapBand(avgValue) });
      const rect = svgEl('rect', {
        x: surface.left + hour * cellWidth,
        y: surface.top + rowIndex * cellHeight,
        width: cellWidth - 1,
        height: cellHeight - 1,
        rx: 2,
        fill: heatmapColor(avgValue, maxValue)
      });
      const title = svgEl('title');
      title.textContent = `${day} ${String(hour).padStart(2, '0')}:00 • ${avgValue === null ? 'No data' : `${avgValue.toFixed(1)} Mbps`} • ${heatmapBand(avgValue)}`;
      rect.appendChild(title);
      surface.svg.appendChild(rect);
    });
  });
  Array.from({ length: 24 }, (_, hour) => hour).forEach(hour => {
    if (hour % 3 !== 0) return;
    const label = svgEl('text', { x: surface.left + hour * cellWidth + cellWidth / 2, y: surface.height - 12, 'text-anchor': 'middle', fill: chartTheme().muted, 'font-size': 11 });
    label.textContent = String(hour);
    surface.svg.appendChild(label);
  });
  const populatedCells = hourlyCells.filter(item => item.avgValue !== null);
  const bestCell = populatedCells.length ? populatedCells.reduce((best, item) => (best === null || (item.avgValue || 0) > (best.avgValue || 0) ? item : best), null) : null;
  const worstCell = populatedCells.length ? populatedCells.reduce((best, item) => (best === null || (item.avgValue || 0) < (best.avgValue || 0) ? item : best), null) : null;
  const goodCells = populatedCells.filter(item => item.band === 'Strong').length;
  const warnCells = populatedCells.filter(item => item.band === 'Acceptable').length;
  const badCells = populatedCells.filter(item => item.band === 'Weak').length;
  const severeCells = populatedCells.filter(item => item.band === 'Severely weak').length;
  const coverage = Math.round((populatedCells.length / hourlyCells.length) * 100);
  let takeaway = 'Mostly acceptable';
  if (goodCells >= Math.max(warnCells + badCells + severeCells, 1)) takeaway = 'Consistently strong';
  else if (badCells + severeCells > goodCells + warnCells) takeaway = 'Recurring weak periods';
  else if (severeCells >= 4) takeaway = 'Severe evening slowdowns';
  renderHeatmapSummary({
    bestLabel: bestCell ? `${bestCell.day.slice(0, 3)} ${String(bestCell.hour).padStart(2, '0')}:00` : 'No data',
    bestValue: bestCell ? bestCell.avgValue : null,
    worstLabel: worstCell ? `${worstCell.day.slice(0, 3)} ${String(worstCell.hour).padStart(2, '0')}:00` : 'No data',
    worstValue: worstCell ? worstCell.avgValue : null,
    takeaway,
    goodCells,
    warnCells,
    badCells,
    severeCells,
    coverage,
  });
  renderHeatmapLegend({ coverage, goodCells, warnCells, badCells, severeCells });
}
function renderScatter(data) {
  const surface = chartSurface('scatter', 320);
  const points = data.filter(item => item.download !== null && item.ping !== null);
  if (!points.length) return;
  const [xMin, xMax] = extent(points.map(item => item.download), 1);
  const [yMin, yMax] = extent(points.map(item => item.ping), 1);
  drawAxes(surface, yMin, yMax, makeTicks(xMin, xMax, 6).map(value => ({
    x: scaleLinear(xMin, xMax, surface.left, surface.width - surface.right)(value),
    label: value.toFixed(0)
  })));
  const scaleX = scaleLinear(xMin, xMax, surface.left, surface.width - surface.right);
  const scaleY = scaleLinear(yMin, yMax, surface.height - surface.bottom, surface.top);
  points.forEach(item => {
    const circle = svgEl('circle', {
      cx: scaleX(item.download),
      cy: scaleY(item.ping),
      r: item.status === 'failed' ? 5 : 4,
      fill: item.status === 'degraded' ? '#f59e0b' : item.status === 'outage' ? '#ef4444' : item.status === 'failed' ? '#f97316' : '#38bdf8',
      opacity: 0.82
    });
    const title = svgEl('title');
    title.textContent = `${item.label} • ${item.download.toFixed(2)} Mbps • ${item.ping.toFixed(2)} ms • ${item.status}`;
    circle.appendChild(title);
    surface.svg.appendChild(circle);
  });
}
function renderDnsCorrelation(data) {
  const dnsChart = document.getElementById('dnsCorrelation');
  const dnsEmpty = document.getElementById('dnsEmpty');
  const dnsLegend = document.getElementById('dnsLegend');
  if (!piholeRows.length) {
    clearNode(dnsChart);
    clearNode(dnsLegend);
    dnsChart.style.display = 'none';
    dnsEmpty.style.display = 'block';
    return;
  }
  dnsChart.style.display = 'block';
  dnsEmpty.style.display = 'none';
  const hourlyDownload = Array.from({length:24}, (_,hour) => {
    const values = data.filter(item => item.hour === hour).map(item => item.download).filter(v => v !== null);
    return values.length ? average(values) : null;
  });
  const dnsByHour = Array.from({length:24}, (_,hour) => {
    const subset = piholeRows.filter(item => new Date(item.datetime).getHours() === hour);
    return {
      dns: average(subset.map(item => item.dnsQueries)),
      blocked: average(subset.map(item => item.blockedQueries))
    };
  });
  const surface = chartSurface('dnsCorrelation', 320);
  const downloadScaleValues = hourlyDownload.map(value => value || 0);
  const queryScaleValues = dnsByHour.flatMap(item => [item.dns || 0, item.blocked || 0]);
  const [leftMin, leftMax] = extent(downloadScaleValues, 1);
  const [rightMin, rightMax] = extent(queryScaleValues, 1);
  drawAxes(surface, leftMin, leftMax, Array.from({ length: 24 }, (_, hour) => hour).filter(hour => hour % 3 === 0).map(hour => ({
    x: scaleLinear(0, 23, surface.left, surface.width - surface.right)(hour),
    label: String(hour)
  })));
  drawRightAxis(surface, rightMin, rightMax, value => `${Math.round(value)}`);
  const scaleX = scaleLinear(0, 23, surface.left, surface.width - surface.right);
  const scaleLeft = scaleLinear(leftMin, leftMax, surface.height - surface.bottom, surface.top);
  const scaleRight = scaleLinear(rightMin, rightMax, surface.height - surface.bottom, surface.top);
  const barWidth = (surface.width - surface.left - surface.right) / 24 / 2.4;
  dnsByHour.forEach((item, hour) => {
    const x = scaleX(hour);
    const dnsHeight = surface.height - surface.bottom - scaleRight(item.dns || 0);
    const blockedHeight = surface.height - surface.bottom - scaleRight(item.blocked || 0);
    surface.svg.appendChild(svgEl('rect', { x: x - barWidth - 1, y: scaleRight(item.dns || 0), width: barWidth, height: dnsHeight, fill: 'rgba(34,197,94,.55)' }));
    surface.svg.appendChild(svgEl('rect', { x: x + 1, y: scaleRight(item.blocked || 0), width: barWidth, height: blockedHeight, fill: 'rgba(245,158,11,.55)' }));
  });
  const line = svgEl('path', {
    d: pathFromPoints(hourlyDownload.map((value, hour) => [scaleX(hour), scaleLeft(value || 0)])),
    fill: 'none',
    stroke: '#38bdf8',
    'stroke-width': 2.4
  });
  surface.svg.appendChild(line);
  const leftLabel = svgEl('text', { x: 18, y: surface.top + (surface.height - surface.top - surface.bottom) / 2, fill: chartTheme().muted, 'font-size': 11, transform: `rotate(-90 18 ${surface.top + (surface.height - surface.top - surface.bottom) / 2})` });
  leftLabel.textContent = 'Average download (Mbps)';
  surface.svg.appendChild(leftLabel);
  const rightLabel = svgEl('text', { x: surface.width - 6, y: surface.top + (surface.height - surface.top - surface.bottom) / 2, fill: chartTheme().muted, 'font-size': 11, transform: `rotate(90 ${surface.width - 6} ${surface.top + (surface.height - surface.top - surface.bottom) / 2})`, 'text-anchor': 'middle' });
  rightLabel.textContent = 'Avg DNS requests / blocked';
  surface.svg.appendChild(rightLabel);

  clearNode(dnsLegend);
  const legendItems = [
    { color: '#38bdf8', label: `Avg download ${average(hourlyDownload.filter(value => value !== null)).toFixed(1)} Mbps` },
    { color: 'rgba(34,197,94,.75)', label: `Avg DNS queries ${average(dnsByHour.map(item => item.dns || 0)).toFixed(0)}/hr` },
    { color: 'rgba(245,158,11,.75)', label: `Avg blocked ${average(dnsByHour.map(item => item.blocked || 0)).toFixed(1)}/hr` }
  ];
  legendItems.forEach(item => {
    const chip = document.createElement('div');
    chip.className = 'legend-chip';
    const swatch = document.createElement('span');
    swatch.className = 'legend-swatch';
    swatch.style.background = item.color;
    chip.appendChild(swatch);
    chip.appendChild(document.createTextNode(item.label));
    dnsLegend.appendChild(chip);
  });
}
function renderScore() {
  setText('scoreSpeed', score.speed.toFixed(1) + ' / 40');
  setText('scoreUpload', score.upload.toFixed(1) + ' / 20');
  setText('scoreLatency', score.latency.toFixed(1) + ' / 20');
  setText('scoreStability', score.stability.toFixed(1) + ' / 20');
  setText('scoreTotal', score.total.toFixed(1) + ' / 100');
  setText('scoreSpeedNote', `Median ${stats.medianDown.toFixed(1)} Mbps, ${stats.pctThreshold.toFixed(1)}% at target`);
  setText('scoreUploadNote', `Average ${stats.avgUp.toFixed(1)} Mbps across valid tests`);
  setText('scoreLatencyNote', `Average ${stats.avgPing.toFixed(2)} ms, high-ping threshold ${thresholds.highPingMs.toFixed(0)} ms`);
  setText('scoreStabilityNote', `${stats.failedCount} failed, ${stats.outageCount} outage, ${stats.degradedCount} degraded`);
  let summary = 'Healthy overall. No obvious recurring problem in the current window.';
  if (score.total < 55) summary = 'Poor overall. Multiple signals are outside the expected range.';
  else if (score.total < 70) summary = 'Below normal overall. One or more components need attention.';
  else if (score.total < 85) summary = 'Usable overall, but not especially clean or consistent.';
  setText('scoreSummary', summary);
  const notes = document.getElementById('scoreNotes');
  clearNode(notes);
  score.explanation.forEach(line => {
    const item = document.createElement('li');
    item.textContent = line;
    notes.appendChild(item);
  });
}
function renderSummary(data) {
  const threshold = Number(document.getElementById('threshold').value || thresholds.degradedDownloadMbps);
  const downloads = data.map(item => item.download).filter(v => v !== null);
  const heroSide = document.querySelector('.hero-side');
  const builtAt = meta.generated_at ? new Date(meta.generated_at).toLocaleString() : 'unknown';
  setText('subtitle', `Interactive history view · dataset ${stats.start} – ${stats.end} · built ${builtAt}`);
  setText('kpiMedian', (quantile(downloads, .5) || 0).toFixed(1) + ' Mbps');
  setText('kpiUpload', average(data.map(item => item.upload)).toFixed(1) + ' Mbps');
  setText('kpiPing', average(data.map(item => item.ping)).toFixed(2) + ' ms');
  setText('kpiFloor', (quantile(downloads, .05) || 0).toFixed(1) + ' Mbps');
  const pct = downloads.length ? downloads.filter(v => v >= threshold).length / downloads.length * 100 : 0;
  setText('kpiThreshold', pct.toFixed(1) + `% ≥ ${threshold} Mbps`);
  setText('kpiFailed', `${data.filter(item => item.isFailed).length} failed`);
  setText('kpiOutage', `${data.filter(item => item.isOutage).length} outage`);
  setText('kpiDegraded', `${data.filter(item => item.isDegraded).length} degraded`);
  const longest = (() => {
    let best = 0, current = 0;
    for (const item of data) {
      if (item.isFailed || item.isOutage) { current += 1; best = Math.max(best, current); }
      else { current = 0; }
    }
    return best;
  })();
  setText('kpiStreak', `${longest} longest outage streak`);
  if (heroSide) setStatusClass(heroSide, 'status-', stats.verdict || 'no_data');
  const verdictBadgeMap = {
    normal: 'Healthy',
    degraded: 'Below Normal',
    outage: 'Problem',
    failed: 'Failed Test',
    no_data: 'No Data'
  };
  const verdictHeadlineMap = {
    normal: 'Connection is performing normally',
    degraded: 'Connection is slower than expected',
    outage: 'Connection problem detected',
    failed: 'Latest connection test failed',
    no_data: 'No connection data yet'
  };
  const latestDown = stats.latestDownload !== null && stats.latestDownload !== undefined ? `${Number(stats.latestDownload).toFixed(1)} Mbps down` : 'download n/a';
  const latestUp = stats.latestUpload !== null && stats.latestUpload !== undefined ? `${Number(stats.latestUpload).toFixed(1)} Mbps up` : 'upload n/a';
  const latestPing = stats.latestPing !== null && stats.latestPing !== undefined ? `${Number(stats.latestPing).toFixed(2)} ms ping` : 'ping n/a';
  setText('verdictBadge', verdictBadgeMap[stats.verdict] || 'Status');
  setText('verdict', verdictHeadlineMap[stats.verdict] || stats.verdictLabel);
  if (stats.verdict === 'normal') {
    setText('verdictCopy', `Latest result: ${latestDown}, ${latestUp}, ${latestPing}. Average ping is ${stats.avgPing.toFixed(2)} ms and ${stats.pctThreshold.toFixed(1)}% of tests met the ${threshold} Mbps target.`);
  } else if (stats.verdict === 'degraded') {
    setText('verdictCopy', `Latest result: ${latestDown}, ${latestUp}, ${latestPing}. The line is usable, but recent performance is under the ${threshold} Mbps target more often than it should be.`);
  } else if (stats.verdict === 'outage') {
    setText('verdictCopy', `Latest result: ${latestDown}, ${latestUp}, ${latestPing}. Recent results include outage-level behaviour or very high latency.`);
  } else if (stats.verdict === 'failed') {
    setText('verdictCopy', `The latest scheduled test did not complete. Recent window still shows ${stats.failedCount} failed tests and ${stats.outageCount} outage-classified results.`);
  } else {
    setText('verdictCopy', 'The dashboard does not have enough recent data to judge the line yet.');
  }
  setText('worstWindow', `Worst window: ${stats.worstWindow}`);
  const linkWrap = document.getElementById('dashboardLinkWrap');
  clearNode(linkWrap);
  if (stats.publicDashboardUrl) {
    const link = document.createElement('a');
    link.href = stats.publicDashboardUrl;
    link.target = '_blank';
    link.rel = 'noreferrer';
    link.textContent = 'Open public dashboard';
    linkWrap.appendChild(link);
  }
}
function render() {
  const data = filteredData();
  const events = filteredEvents();
  renderFreshness();
  renderSummary(data);
  renderTimeline(data, events);
  renderHeatmap(data);
  renderScatter(data);
  renderDnsCorrelation(data);
  renderDiagnosis();
  renderFirewallNoise();
  renderTable(events);
  renderInventoryMeta();
  renderDeviceMap();
  renderScore();
}
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (getThemeChoice() === 'auto') applyTheme('auto'); });
window.addEventListener('resize', () => render());
document.getElementById('theme').value = getThemeChoice();
document.getElementById('theme').addEventListener('change', event => applyTheme(event.target.value));
document.getElementById('metric').addEventListener('change', render);
document.getElementById('threshold').value = stats.thresholdMbps;
document.getElementById('threshold').addEventListener('input', render);
document.getElementById('dayFilter').addEventListener('change', render);
document.getElementById('severityFilter').addEventListener('change', render);
document.getElementById('eventTypeFilter').addEventListener('change', render);
document.getElementById('nmapScanButton').addEventListener('click', triggerNmapScan);
document.getElementById('diagEvidenceToggle').addEventListener('click', () => { diagView = 'evidence'; renderDiagnosis(); });
document.getElementById('diagActionsToggle').addEventListener('click', () => { diagView = 'actions'; renderDiagnosis(); });
document.getElementById('diagFocusEvents').addEventListener('click', focusDiagnosisEvents);
document.getElementById('diagFocusExtender').addEventListener('click', focusSuspectDevice);
initFilters();
initActionTokenControl();
applyTheme(getThemeChoice());
</script>
</body>
</html>
"""
    return template.replace('__PAYLOAD_JSON__', payload_json)


def generate_premium_dashboard(history: dict[str, list[dict[str, Any]]], now: datetime, chart_path: str, speed_result: SpeedResult) -> tuple[bool, str]:
    if plt is None or mdates is None:
        return False, "matplotlib not installed"

    rows = _merge_history(history, now, days=30)
    if not rows:
        return False, "No speed data available for premium dashboard"

    data_rows = [
        {"recorded_at": row.timestamp.isoformat(), "speed_ok": True, "download_mbps": row.download, "upload_mbps": row.upload, "ping_ms": row.ping}
        for row in rows
    ]
    thresholds = _build_thresholds(None)
    classified_rows = _rows_from_run_records(data_rows, history, now, thresholds, days=30)
    payload = _build_dashboard_payload(classified_rows, [], [], [], {}, thresholds, output_path=chart_path)
    stats = payload["stats"]
    figure = plt.figure(figsize=(16, 10), facecolor="#111827")
    gs = figure.add_gridspec(3, 12, height_ratios=[1.0, 2.2, 2.0], hspace=0.28, wspace=0.42)

    figure.text(0.04, 0.95, "Internet Health Snapshot", color="#f8fafc", fontsize=26, fontweight="bold", ha="left", va="top")
    figure.text(
        0.04,
        0.915,
        f"Local history · {stats['start']} – {stats['end']} · {stats['tests']} tests",
        color="#94a3b8",
        fontsize=13,
        ha="left",
        va="top",
    )

    cards = [
        ("Typical download", f"{stats['medianDown']:.0f} Mbps", f"Average {stats['avgDown']:.0f} Mbps"),
        ("Average upload", f"{stats['avgUp']:.1f} Mbps", f"{stats['pctThreshold']:.0f}% ≥ {thresholds.degraded_download_mbps:.0f} Mbps"),
        ("Average ping", f"{stats['avgPing']:.1f} ms", f"Reliability floor {stats['p05']:.0f} Mbps"),
        ("Quality score", f"{payload['score']['total']:.0f}/100", f"Failed {stats['failedCount']} · outage {stats['outageCount']} · degraded {stats['degradedCount']}"),
    ]
    for idx, (title, value, subtitle) in enumerate(cards):
        ax = figure.add_subplot(gs[0, idx * 12 // 4 : (idx + 1) * 12 // 4])
        ax.set_facecolor("#152033")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.text(0.06, 0.74, title, transform=ax.transAxes, color="#cbd5e1", fontsize=12, fontweight="bold", ha="left")
        ax.text(0.06, 0.40, value, transform=ax.transAxes, color="#f8fafc", fontsize=27, fontweight="bold", ha="left")
        ax.text(0.06, 0.18, subtitle, transform=ax.transAxes, color="#94a3b8", fontsize=10.5, ha="left")

    def style_panel(ax: Any, title: str, subtitle: str | None = None) -> Any:
        ax.set_facecolor("#152033")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.text(0.04, 0.94, title, transform=ax.transAxes, color="#f8fafc", fontsize=16.5, fontweight="bold", ha="left", va="top")
        if subtitle:
            ax.text(0.04, 0.86, subtitle, transform=ax.transAxes, color="#94a3b8", fontsize=10, ha="left", va="top")
        inner = ax.inset_axes([0.05, 0.12, 0.90, 0.68])
        inner.set_facecolor("#152033")
        inner.grid(color="#334155", linewidth=0.8, alpha=0.65)
        inner.tick_params(colors="#cbd5e1", labelsize=10)
        for spine in inner.spines.values():
            spine.set_color("#334155")
        return inner

    by_day: dict[str, list[float]] = {}
    for row in classified_rows:
        if row.download is None:
            continue
        by_day.setdefault(row.timestamp.strftime("%Y-%m-%d"), []).append(row.download)
    day_dates = [datetime.fromisoformat(day) for day in sorted(by_day)]
    day_median = [_quantile(by_day[day.strftime("%Y-%m-%d")], 0.5) or 0.0 for day in day_dates]
    day_average = [average(by_day[day.strftime("%Y-%m-%d")]) or 0.0 for day in day_dates]
    day_low = [min(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]
    day_high = [max(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]

    ax_band_panel = figure.add_subplot(gs[1, :7])
    ax_band = style_panel(ax_band_panel, "Daily Download Reliability Band", "Median, average, and spread across the last 30 days.")
    ax_band.fill_between(day_dates, day_low, day_high, color="#1d4ed8", alpha=0.18)
    ax_band.plot(day_dates, day_median, color="#38bdf8", linewidth=2.4, label="Median")
    ax_band.plot(day_dates, day_average, color="#fb923c", linewidth=1.6, linestyle="--", label="Average")
    ax_band.set_ylabel("Mbps", color="#cbd5e1")
    band_locator = mdates.AutoDateLocator(minticks=4, maxticks=6)
    ax_band.xaxis.set_major_locator(band_locator)
    ax_band.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    ax_band.xaxis.get_offset_text().set_visible(False)
    ax_band.legend(loc="lower right", frameon=False, labelcolor="#cbd5e1")

    heat_values = [[None for _ in range(24)] for _ in range(7)]
    for dow_idx, day_name in enumerate(DAY_NAMES):
        for hour in range(24):
            hour_values = [
                row.download for row in classified_rows
                if row.download is not None and row.timestamp.strftime("%A") == day_name and row.timestamp.hour == hour
            ]
            heat_values[dow_idx][hour] = average(hour_values)
    ax_heat_panel = figure.add_subplot(gs[1, 7:])
    ax_heat = style_panel(ax_heat_panel, "Traffic-Light Speed Heatmap", "Average download by weekday and hour.")
    image = ax_heat.imshow(heat_values, aspect="auto", cmap="viridis")
    ax_heat.set_yticks(range(7), [name[:3] for name in DAY_NAMES], color="#cbd5e1")
    ax_heat.set_xticks(range(0, 24, 3))
    ax_heat.set_xticklabels([str(hour) for hour in range(0, 24, 3)], color="#cbd5e1")
    cbar = figure.colorbar(image, ax=ax_heat, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(colors="#cbd5e1")

    hourly_values: list[list[float]] = [[] for _ in range(24)]
    for row in classified_rows:
        if row.download is not None:
            hourly_values[row.timestamp.hour].append(row.download)
    hour_avg = [average(values) if values else None for values in hourly_values]
    hour_low = [min(values) if values else None for values in hourly_values]
    hour_high = [max(values) if values else None for values in hourly_values]
    valid_hours = [hour for hour, value in enumerate(hour_avg) if value is not None]
    valid_avg = [hour_avg[hour] for hour in valid_hours]
    valid_low = [hour_low[hour] for hour in valid_hours]
    valid_high = [hour_high[hour] for hour in valid_hours]

    ax_times_panel = figure.add_subplot(gs[2, :7])
    ax_times = style_panel(ax_times_panel, "Best and Slowest Times of Day", "Hourly average with low/high spread.")
    ax_times.fill_between(valid_hours, valid_low, valid_high, color="#1d4ed8", alpha=0.18)
    ax_times.plot(valid_hours, valid_avg, color="#38bdf8", linewidth=2.4)
    if valid_avg:
        best_hour_index = valid_hours[max(range(len(valid_avg)), key=lambda idx: valid_avg[idx])]
        slow_hour_index = valid_hours[min(range(len(valid_avg)), key=lambda idx: valid_avg[idx])]
        ax_times.scatter([best_hour_index], [hour_avg[best_hour_index]], color="#22c55e", s=60, zorder=5)
        ax_times.scatter([slow_hour_index], [hour_avg[slow_hour_index]], color="#f97316", s=60, zorder=5)
    ax_times.set_xlabel("Hour of day", color="#cbd5e1")
    ax_times.set_ylabel("Mbps", color="#cbd5e1")
    ax_times.xaxis.set_major_locator(mticker.MultipleLocator(2))

    ax_exec = figure.add_subplot(gs[2, 7:])
    ax_exec.set_facecolor("#152033")
    ax_exec.set_xticks([])
    ax_exec.set_yticks([])
    for spine in ax_exec.spines.values():
        spine.set_visible(False)
    ax_exec.text(0.04, 0.92, "What Stands Out", transform=ax_exec.transAxes, color="#f8fafc", fontsize=17, fontweight="bold", ha="left")
    lines = [
        f"• Typical result: {stats['medianDown']:.0f} Mbps down",
        f"• Reliability floor: {stats['p05']:.0f} Mbps",
        f"• Peak band: {stats['p95']:.0f} Mbps",
        f"• Failed tests: {stats['failedCount']}",
        f"• Outage-classified tests: {stats['outageCount']}",
        f"• Longest outage streak: {stats['longestOutageStreak']}",
    ]
    for idx, line in enumerate(lines):
        ax_exec.text(0.06, 0.80 - idx * 0.10, line, transform=ax_exec.transAxes, color="#cbd5e1", fontsize=12.2, ha="left")

    figure.text(
        0.04,
        0.025,
        "Shaded bands show normal variation. Heatmap shows recurring time-of-day patterns. Quality score is explainable in the interactive dashboard.",
        color="#94a3b8",
        fontsize=10,
        ha="left",
    )

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Premium dashboard generated"


def _version_string() -> str:
    try:
        from .version_check import current_version

        package_version = current_version()
    except Exception:
        package_version = None
    if package_version:
        return package_version
    try:
        return importlib_metadata.version("pi-probe-discord")
    except importlib_metadata.PackageNotFoundError:
        pass
    changelog_path = Path(__file__).resolve().parents[1] / "debian" / "changelog"
    try:
        first_line = changelog_path.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError):
        return "unknown"
    match = re.search(r"\(([^)]+)\)", first_line)
    if not match:
        return "unknown"
    return match.group(1)


def run_dashboard_nmap_scan(output_path: str) -> dict[str, Any]:
    from .config import load_config
    from .nmap_inventory import run_nmap_inventory_scan
    from .pihole_hourly import export_pihole_hourly_csv
    from .storage import load_history_from_db, load_probe_runs_from_db

    config = load_config()
    now = datetime.now().astimezone()
    scan_ok, scan_message = run_nmap_inventory_scan(config, now)
    response: dict[str, Any] = {
        "ok": False,
        "scanOk": scan_ok,
        "refreshOk": False,
        "message": scan_message,
    }
    if not scan_ok:
        return response

    history = load_history_from_db(config, now)
    run_rows = load_probe_runs_from_db(config, now, days=30)
    export_pihole_hourly_csv(config, now, days=30)
    refresh_ok, refresh_message = generate_interactive_dashboard(
        history,
        now,
        output_path,
        config=config,
        run_rows=run_rows,
    )
    response["refreshOk"] = refresh_ok
    response["ok"] = refresh_ok
    response["message"] = refresh_message if refresh_ok else f"{scan_message}; dashboard refresh failed: {refresh_message}"
    return response


def apply_dashboard_nmap_override(output_path: str, payload: dict[str, Any]) -> dict[str, Any]:
    from .config import load_config
    from .nmap_inventory import export_nmap_inventory_json, remove_nmap_override, upsert_nmap_override
    from .pihole_hourly import export_pihole_hourly_csv
    from .storage import load_history_from_db, load_probe_runs_from_db

    config = load_config()
    selector = payload.get("selector") if isinstance(payload.get("selector"), dict) else {}
    ip = str(selector.get("ip") or "").strip()
    mac = str(selector.get("mac") or "").strip()
    hostname = str(selector.get("hostname") or "").strip()
    action = str(payload.get("action") or "set").strip().lower()
    try:
        if action == "clear":
            message = remove_nmap_override(config, ip=ip, mac=mac, hostname=hostname)
        else:
            message = upsert_nmap_override(
                config,
                ip=ip,
                mac=mac,
                hostname=hostname,
                name=str(payload.get("name") or "").strip(),
                category=str(payload.get("category") or "").strip(),
            )
    except RuntimeError as exc:
        return {"ok": False, "message": str(exc)}

    now = datetime.now().astimezone()
    export_ok, export_message = export_nmap_inventory_json(config, now)
    if not export_ok:
        return {"ok": False, "message": f"{message}; inventory refresh failed: {export_message}"}
    history = load_history_from_db(config, now)
    run_rows = load_probe_runs_from_db(config, now, days=30)
    export_pihole_hourly_csv(config, now, days=30)
    refresh_ok, refresh_message = generate_interactive_dashboard(
        history,
        now,
        output_path,
        config=config,
        run_rows=run_rows,
    )
    if not refresh_ok:
        return {"ok": False, "message": f"{message}; dashboard refresh failed: {refresh_message}"}
    return {"ok": True, "message": message}


def ping_dashboard_device(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload.get("ip") or payload.get("hostname") or "").strip()
    label = str(payload.get("name") or target or "device").strip()
    if not target:
        return {"ok": False, "message": "Ping target missing."}
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", target):
        return {"ok": False, "message": "Ping target contains unsupported characters."}

    ok, output = _run_optional_command(["ping", "-c", "1", "-W", "1", target], timeout=3)
    if ok:
        latency_match = re.search(r"time=([0-9.]+)\s*ms", output)
        if latency_match:
            return {"ok": True, "message": f"{label} reachable: {latency_match.group(1)} ms"}
        return {"ok": True, "message": f"{label} reachable"}
    if output:
        return {"ok": False, "message": f"{label} unreachable: {output.splitlines()[-1][:160]}"}
    return {"ok": False, "message": f"{label} unreachable"}


def _load_allowed_ping_targets() -> set[str]:
    try:
        from .config import load_config

        config = load_config(require_webhook=False)
        rows, _ = load_dashboard_nmap_inventory(config)
    except Exception:
        return set()
    targets: set[str] = set()
    for row in rows:
        for value in (row.ip, row.hostname, row.name):
            if value:
                targets.add(value)
    return targets


def serve_interactive_dashboard(
    output_path: str,
    host: str,
    port: int,
    *,
    tls_enabled: bool = False,
    tls_cert_file: str = "",
    tls_key_file: str = "",
    api_token: str = "",
) -> int:
    file_path = Path(output_path).resolve()
    directory = file_path.parent
    status_path = directory / STATUS_FILE_NAME

    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(directory), **kwargs)

        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            super().end_headers()

        def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _actions_authorized(self) -> bool:
            if api_token:
                supplied = self.headers.get("X-Pi-Probe-Token", "")
                return hmac.compare_digest(supplied, api_token)
            return False

        def _read_json_payload(self) -> dict[str, Any] | None:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0
            if content_length > DASHBOARD_ACTION_MAX_BODY_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "message": "JSON payload too large"})
                return None
            try:
                raw = self.rfile.read(content_length) if content_length > 0 else b"{}"
                payload = json.loads(raw.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Invalid JSON payload"})
                return None
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "JSON payload must be an object"})
                return None
            return payload

        def do_GET(self) -> None:  # noqa: N802
            request_path = urlparse(self.path).path
            if request_path == "/healthz":
                payload = b"ok\n"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if request_path == "/status.json":
                try:
                    payload = status_path.read_bytes()
                except OSError:
                    payload = json.dumps(
                        {
                            "service": SERVICE_NAME,
                            "generated_at": "",
                            "dataset_start": "",
                            "dataset_end": "",
                            "test_count": 0,
                            "dashboard_file": file_path.name,
                            "version": _version_string(),
                            "refreshed": {
                                "dashboard": "",
                                "speed": "",
                                "events": "",
                                "inventory": "",
                                "pihole": "",
                                "diagnosis": "",
                            },
                        }
                    ).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if request_path in {"/", ""}:
                self.path = f"/{file_path.name}"
            elif request_path != f"/{file_path.name}":
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"})
                return
            else:
                self.path = request_path
            return super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            request_path = urlparse(self.path).path
            if request_path not in {"/api/nmap/scan", "/api/nmap/override", "/api/device/ping"}:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"})
                return
            if not self._actions_authorized():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "message": "Dashboard action token required"})
                return
            if request_path == "/api/nmap/scan":
                result = run_dashboard_nmap_scan(str(file_path))
                status = HTTPStatus.OK if result.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR
                self._send_json(status, result)
                return
            if request_path == "/api/nmap/override":
                payload = self._read_json_payload()
                if payload is None:
                    return
                result = apply_dashboard_nmap_override(str(file_path), payload)
                status = HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST
                self._send_json(status, result)
                return
            if request_path == "/api/device/ping":
                payload = self._read_json_payload()
                if payload is None:
                    return
                target = str(payload.get("ip") or payload.get("hostname") or "").strip()
                if target not in _load_allowed_ping_targets():
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Ping target is not in current inventory"})
                    return
                result = ping_dashboard_device(payload)
                status = HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST
                self._send_json(status, result)
                return

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    scheme = "http"
    if tls_enabled:
        cert_path = Path(tls_cert_file)
        key_path = Path(tls_key_file)
        if not cert_path.exists():
            raise RuntimeError(f"Dashboard TLS cert file not found: {cert_path}")
        if not key_path.exists():
            raise RuntimeError(f"Dashboard TLS key file not found: {key_path}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"Serving interactive dashboard at {scheme}://{host}:{port}/{file_path.name}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
