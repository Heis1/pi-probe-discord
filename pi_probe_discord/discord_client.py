from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from .models import AppConfig, PiholeResult, RouterSnapshot, SpeedResult, UpdateResult
from .firewall import FirewallSnapshot
from .status import assess_internet_health


def build_embed(
    config: AppConfig,
    hostname: str,
    run_at_local: str,
    history: dict[str, list[dict[str, Any]]],
    update_result: UpdateResult,
    pihole_result: PiholeResult,
    speed_result: SpeedResult,
    probe_version_line: str | None = None,
    firewall_snapshot: FirewallSnapshot | None = None,
    router_snapshot: RouterSnapshot | None = None,
    dashboard_summary: dict[str, Any] | None = None,
    include_diagnostics: bool = True,
) -> dict[str, Any]:
    warnings: list[str] = []
    warnings.extend(pihole_result.warnings)
    warnings.extend(speed_result.warnings)

    latest_time = history["download"][-1]["x"] if history.get("download") else ""
    if latest_time:
        try:
            assessment = assess_internet_health(history, datetime.fromisoformat(latest_time), speed_result)
        except ValueError:
            assessment = assess_internet_health(history, datetime.now().astimezone(), speed_result)
    else:
        assessment = assess_internet_health(history, datetime.now().astimezone(), speed_result)

    plain_summary = {
        "INTERNET HEALTHY": "Internet looks normal right now.",
        "INTERNET SLOWER THAN NORMAL": "Internet is working, but slower than your usual range.",
        "INTERNET DEGRADED": "Internet problem detected right now.",
        "WAITING FOR DATA": "Still building enough local history to judge the connection.",
    }.get(assessment.label, assessment.headline)

    title = "✅ Internet Looks Normal"
    color = assessment.discord_color
    description = plain_summary

    if not speed_result.ok:
        title = "⚠️ Speed Test Failed"
        color = 16766720
        description = "The speed test did not complete, so no reliable internet health verdict was produced."
    elif assessment.label == "WAITING FOR DATA":
        title = "⏳ Building Local Baseline"
        color = 16766720
        description = plain_summary
    elif assessment.label == "INTERNET SLOWER THAN NORMAL":
        title = "⚠️ Internet Slower Than Usual"
    elif assessment.label == "INTERNET DEGRADED":
        title = "❌ Internet Speed Reduced"
        description = "Download speed is significantly below its usual level for this time of day."

    if not update_result.ok:
        title = "❌ Update Failed"
        color = 15158332
        description = f"Update failed: {update_result.error}"
    elif warnings:
        description += "\nAdditional warnings were recorded."

    speed_value = speed_result.summary
    if warnings:
        speed_value += "\n" + "\n".join(f"- {item}" for item in warnings[:5])

    if not include_diagnostics:
        baseline_value = (
            f"Download {assessment.download_baseline:.1f} Mbps | "
            f"Upload {assessment.upload_baseline:.1f} Mbps | "
            f"Ping {assessment.ping_baseline:.1f} ms"
            if assessment.download_baseline is not None
            and assessment.upload_baseline is not None
            and assessment.ping_baseline is not None
            else "Still establishing a local baseline"
        )
        download_change = ""
        if assessment.download_baseline and speed_result.download_mbps is not None:
            change = (speed_result.download_mbps / assessment.download_baseline - 1) * 100
            download_change = f" Download is {abs(change):.0f}% {'below' if change < 0 else 'above'} usual."
        if assessment.label == "INTERNET DEGRADED":
            action = "Recheck at the next interval. If it remains reduced, check the WAN/ISP connection before changing Wi-Fi equipment."
        elif assessment.label == "INTERNET SLOWER THAN NORMAL":
            action = "No immediate action. Recheck at the next interval and investigate only if the slowdown persists."
        elif assessment.label == "INTERNET HEALTHY":
            action = "No action required."
        else:
            action = "Allow a few more scheduled checks to establish a reliable baseline."
        fields = [
            {"name": "Measured now", "value": speed_value[:1024], "inline": False},
            {"name": "Usual at this time", "value": baseline_value[:1024], "inline": False},
            {"name": "Assessment", "value": (assessment.detail + download_change)[:1024], "inline": False},
            {"name": "Next action", "value": action, "inline": False},
        ]
        return {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": f"{hostname} | {run_at_local}"},
            }]
        }

    fields: list[dict[str, Any]] = [
        {"name": "What This Means", "value": assessment.headline[:1024], "inline": False},
        {"name": "Now", "value": speed_value[:1024], "inline": False},
        {
            "name": "Pi-hole",
            "value": (
                f"Service: {pihole_result.service_status}\n"
                f"Blocking: {pihole_result.blocking_status}\n"
                f"Updates: {pihole_result.update_status}"
            ),
            "inline": True,
        },
        {"name": "Host", "value": f"`{hostname}`\n{run_at_local}", "inline": True},
        {"name": "Why It Was Flagged", "value": assessment.detail[:1024], "inline": True},
        {"name": "Gravity / Blocklist", "value": f"{pihole_result.gravity_age}\n{pihole_result.blocklist_count}", "inline": False},
        {"name": "Probe Version", "value": (probe_version_line or "Version check not run")[:1024], "inline": False},
        {"name": "Recent Update Summary", "value": f"```text\n{update_result.summary[:900]}\n```", "inline": False},
    ]

    public_url = ""
    if dashboard_summary:
        stats = dashboard_summary.get("stats", {})
        score = dashboard_summary.get("score", {})
        threshold = stats.get("thresholdMbps", 250)
        fields.extend(
            [
                {
                    "name": "Dashboard Summary",
                    "value": (
                        f"Quality score: {score.get('total', 0):.1f}/100\n"
                        f"Median download: {stats.get('medianDown', 0):.1f} Mbps\n"
                        f"Average upload: {stats.get('avgUp', 0):.1f} Mbps\n"
                        f"Average ping: {stats.get('avgPing', 0):.2f} ms"
                    )[:1024],
                    "inline": False,
                },
                {
                    "name": "Reliability Snapshot",
                    "value": (
                        f"Reliability floor: {stats.get('p05', 0):.1f} Mbps\n"
                        f"Tests ≥ {threshold:.0f} Mbps: {stats.get('pctThreshold', 0):.1f}%\n"
                        f"Outage count: {stats.get('outageCount', 0)}\n"
                        f"Failed test count: {stats.get('failedCount', 0)}\n"
                        f"Degraded test count: {stats.get('degradedCount', 0)}"
                    )[:1024],
                    "inline": False,
                },
            ]
        )
        public_url = str(stats.get("publicDashboardUrl") or config.public_dashboard_url or "")
        if public_url:
            fields.append(
                {
                    "name": config.dashboard_link_label[:256],
                    "value": public_url[:1024],
                    "inline": False,
                }
            )

    if firewall_snapshot is not None:
        status_value = "UFW active" if firewall_snapshot.status.active else "UFW inactive"
        policy_value = f"{firewall_snapshot.status.default_incoming} in / {firewall_snapshot.status.default_outgoing} out"
        top_sources = ", ".join(f"{src} ({count})" for src, count in firewall_snapshot.top_sources[:3]) or "None"
        top_ports = ", ".join(f"{port} ({count})" for port, count in firewall_snapshot.top_ports[:3]) or "None"
        note = firewall_snapshot.notes[0] if firewall_snapshot.notes else "Blocked traffic is not automatically bad. It often means the firewall is doing its job."
        fields.extend(
            [
                {"name": "Firewall Snapshot / Status", "value": status_value[:1024], "inline": True},
                {"name": "Firewall Snapshot / Policy", "value": policy_value[:1024], "inline": True},
                {"name": "Firewall Snapshot / Last 24h blocks", "value": str(firewall_snapshot.blocked_entries), "inline": True},
                {"name": "Firewall Snapshot / Top sources", "value": top_sources[:1024], "inline": False},
                {"name": "Firewall Snapshot / Top ports", "value": top_ports[:1024], "inline": False},
                {"name": "Firewall Snapshot / Notes", "value": note[:1024], "inline": False},
            ]
        )

    if router_snapshot is not None and router_snapshot.enabled:
        top_sources = ", ".join(f"{src} ({count})" for src, count in router_snapshot.top_sources[:3]) or "None"
        top_oids = ", ".join(f"{oid} ({count})" for oid, count in router_snapshot.top_trap_oids[:3]) or "None"
        note = router_snapshot.notes[0] if router_snapshot.notes else "SNMP trap ingest is active."
        fields.extend(
            [
                {
                    "name": "Router SNMP / Last ingest",
                    "value": f"{router_snapshot.ingested_events} new events",
                    "inline": True,
                },
                {
                    "name": "Router SNMP / Window events",
                    "value": f"{router_snapshot.recent_events} in {router_snapshot.window_hours}h",
                    "inline": True,
                },
                {
                    "name": "Router SNMP / LinkDown + AuthFail",
                    "value": f"{router_snapshot.link_down_events} + {router_snapshot.auth_fail_events}",
                    "inline": True,
                },
                {
                    "name": "Router SNMP / Severity",
                    "value": ", ".join(
                        f"{name}:{count}" for name, count in sorted(router_snapshot.severity_counts.items())
                    )[:1024]
                    or "none",
                    "inline": False,
                },
                {"name": "Router SNMP / Top sources", "value": top_sources[:1024], "inline": False},
                {"name": "Router SNMP / Top trap OIDs", "value": top_oids[:1024], "inline": False},
                {"name": "Router SNMP / Notes", "value": note[:1024], "inline": False},
            ]
        )

    embed: dict[str, Any] = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": f"log: {config.log_file}"},
    }
    if public_url:
        embed["url"] = public_url
    return {"embeds": [embed]}


def post_webhook_json(config: AppConfig, payload: dict[str, Any]) -> None:
    response = requests.post(config.webhook_url, json=payload, timeout=config.request_timeout)
    response.raise_for_status()


def post_webhook_file(config: AppConfig, payload_json: dict[str, Any], image_path: str) -> None:
    with Path(image_path).open("rb") as image_handle:
        response = requests.post(
            config.webhook_url,
            data={"payload_json": json.dumps(payload_json)},
            files={"file": (Path(image_path).name, image_handle, "image/png")},
            timeout=config.request_timeout,
        )
    response.raise_for_status()
