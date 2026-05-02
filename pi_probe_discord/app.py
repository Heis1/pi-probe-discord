from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path

import requests

from .charts import generate_chart
from .config import load_config
from .discord_client import build_embed, post_webhook_file, post_webhook_json
from .firewall import (
    FirewallConfig,
    collect_firewall_snapshot,
    format_firewall_snapshot_json,
    format_firewall_snapshot_text,
)
from .models import PiholeResult, RunRecord, SpeedResult, UpdateResult
from .speedtest_runner import run_speedtest_measurement
from .storage import build_report, init_database, load_history_from_db, save_run_record
from .system_checks import collect_pihole_info, run_updates
from .version_check import version_status_line


def _read_last_firewall_alert_sent_at(state_file: Path) -> datetime | None:
    try:
        raw = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    value = raw.get("last_sent_at")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _write_last_firewall_alert_sent_at(state_file: Path, sent_at: datetime) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"last_sent_at": sent_at.isoformat()}), encoding="utf-8")


def _build_firewall_alert_payload(
    hostname: str,
    run_at_local: str,
    snapshot,
    reasons: list[str],
) -> dict[str, object]:
    top_sources = ", ".join(f"{src} ({count})" for src, count in snapshot.top_sources[:3]) or "None"
    top_ports = ", ".join(f"{port} ({count})" for port, count in snapshot.top_ports[:3]) or "None"
    return {
        "embeds": [
            {
                "title": "🚨 Firewall Attack Alert",
                "description": "Suspicious firewall activity crossed configured alert thresholds.",
                "color": 15158332,
                "fields": [
                    {"name": "Host", "value": f"`{hostname}`\n{run_at_local}", "inline": True},
                    {"name": "Window", "value": f"{snapshot.window_hours}h", "inline": True},
                    {"name": "Reason", "value": "\n".join(f"- {item}" for item in reasons)[:1024], "inline": False},
                    {"name": "Blocked entries", "value": str(snapshot.blocked_entries), "inline": True},
                    {"name": "SSH attempts (DPT=22)", "value": str(snapshot.ssh_attempts), "inline": True},
                    {"name": "Noisy sources", "value": str(len(snapshot.noisy_sources)), "inline": True},
                    {"name": "Top sources", "value": top_sources[:1024], "inline": False},
                    {"name": "Top ports", "value": top_ports[:1024], "inline": False},
                    {"name": "Log source", "value": snapshot.log_source[:1024], "inline": False},
                ],
            }
        ]
    }


def _evaluate_firewall_alert(snapshot, config) -> list[str]:
    reasons: list[str] = []
    if snapshot.blocked_entries >= config.firewall_alert_min_blocks:
        reasons.append(
            f"Blocked entries {snapshot.blocked_entries} >= threshold {config.firewall_alert_min_blocks}"
        )
    if snapshot.ssh_attempts >= config.firewall_alert_min_ssh_attempts:
        reasons.append(
            f"SSH attempts {snapshot.ssh_attempts} >= threshold {config.firewall_alert_min_ssh_attempts}"
        )
    if len(snapshot.noisy_sources) >= config.firewall_alert_min_noisy_sources:
        reasons.append(
            f"Noisy sources {len(snapshot.noisy_sources)} >= threshold {config.firewall_alert_min_noisy_sources}"
        )
    return reasons


def build_run_record(
    run_at: datetime,
    hostname: str,
    update_result: UpdateResult,
    pihole_result: PiholeResult,
    speed_result: SpeedResult,
) -> RunRecord:
    return RunRecord(
        recorded_at=run_at,
        hostname=hostname,
        update_ok=update_result.ok,
        update_summary=update_result.summary,
        update_error=update_result.error,
        pihole_service_status=pihole_result.service_status,
        pihole_blocking_status=pihole_result.blocking_status,
        pihole_gravity_age=pihole_result.gravity_age,
        pihole_blocklist_count=pihole_result.blocklist_count,
        pihole_warnings=" | ".join(pihole_result.warnings),
        speed_ok=speed_result.ok,
        speed_summary=speed_result.summary,
        download_mbps=speed_result.download_mbps,
        upload_mbps=speed_result.upload_mbps,
        ping_ms=speed_result.ping_ms,
        speed_warnings=" | ".join(speed_result.warnings),
    )


def run_mode(mode: str) -> int:
    config = load_config()
    init_database(config)

    hostname = socket.gethostname()
    run_at = datetime.now().astimezone()
    run_at_local = run_at.strftime("%Y-%m-%d %H:%M:%S %Z")
    update_result = UpdateResult(ok=True, summary="Update step not run for this mode.")
    pihole_result = PiholeResult(service_status="Not run", blocking_status="Not run", gravity_age="Not run", blocklist_count="Not run")
    speed_result = SpeedResult(ok=False, summary="Speed test not run for this mode.")

    if mode in {"full", "update-only"}:
        update_result = run_updates(hostname, run_at_local, Path(config.log_file))
        pihole_result = collect_pihole_info()
    if mode in {"full", "speedtest-only"}:
        speed_result = run_speedtest_measurement()

    save_run_record(config, build_run_record(run_at, hostname, update_result, pihole_result, speed_result))

    if mode in {"full", "speedtest-only"} and speed_result.ok:
        history = load_history_from_db(config, run_at)
        chart_ok, chart_message = generate_chart(history, run_at, config.chart_file, speed_result)
        speed_result.chart_generated = chart_ok
        if not chart_ok:
            speed_result.warnings.append(chart_message)
    else:
        history = load_history_from_db(config, run_at)

    version_line = version_status_line(timeout=config.request_timeout) if mode == "full" else None
    firewall_snapshot = None
    if mode == "full" and config.firewall_enabled:
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
        if config.firewall_alert_enabled and firewall_snapshot.status.active:
            reasons = _evaluate_firewall_alert(firewall_snapshot, config)
            if reasons:
                state_file = Path(config.firewall_alert_state_file)
                last_sent_at = _read_last_firewall_alert_sent_at(state_file)
                cooldown_seconds = config.firewall_alert_cooldown_minutes * 60
                should_send = True
                if last_sent_at is not None and last_sent_at.tzinfo is not None:
                    age = (run_at - last_sent_at).total_seconds()
                    if age < cooldown_seconds:
                        should_send = False
                if should_send:
                    alert_payload = _build_firewall_alert_payload(hostname, run_at_local, firewall_snapshot, reasons)
                    try:
                        post_webhook_json(config, alert_payload)
                        _write_last_firewall_alert_sent_at(state_file, run_at)
                    except requests.RequestException as exc:
                        raise RuntimeError(f"Discord firewall alert POST failed: {exc}") from exc

    payload = build_embed(
        config,
        hostname,
        run_at_local,
        history,
        update_result,
        pihole_result,
        speed_result,
        version_line,
        firewall_snapshot,
    )
    try:
        if speed_result.chart_generated and Path(config.chart_file).exists():
            post_webhook_file(config, payload, config.chart_file)
        else:
            post_webhook_json(config, payload)
    except requests.RequestException as exc:
        raise RuntimeError(f"Discord webhook POST failed: {exc}") from exc

    return 0


def render_report(days: int) -> str:
    config = load_config(require_webhook=False)
    init_database(config)
    return build_report(config, days)


def render_firewall_report(window_hours: int | None = None, as_json: bool = False) -> str:
    config = load_config(require_webhook=False)
    firewall_config = FirewallConfig(
        enabled=config.firewall_enabled,
        window_hours=window_hours or config.firewall_window_hours,
        top_n=config.firewall_top_n,
        noisy_source_threshold=config.firewall_noisy_source_threshold,
        include_allow=config.firewall_include_allow,
        log_paths=config.firewall_log_paths,
    )
    snapshot = collect_firewall_snapshot(firewall_config)
    if as_json:
        return format_firewall_snapshot_json(snapshot)
    return format_firewall_snapshot_text(snapshot, detailed=True)
