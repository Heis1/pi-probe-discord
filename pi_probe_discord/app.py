from __future__ import annotations

import json
import socket
import subprocess
from datetime import datetime
from pathlib import Path

import requests

from .charts import generate_chart
from .config import load_config
from .dashboard import (
    build_network_diagnosis,
    build_dashboard_summary,
    generate_interactive_dashboard,
    generate_premium_dashboard,
    load_dashboard_events,
    load_dashboard_nmap_inventory,
    serve_interactive_dashboard,
)
from .discord_client import build_embed, post_webhook_file, post_webhook_json
from .firewall import (
    FirewallConfig,
    collect_firewall_snapshot,
    format_firewall_snapshot_json,
    format_firewall_snapshot_text,
)
from .firewall_charts import generate_firewall_chart
from .models import PiholeResult, RunRecord, SpeedResult, UpdateResult
from .nmap_inventory import (
    export_nmap_inventory_json,
    list_nmap_devices,
    remove_nmap_override,
    run_nmap_inventory_scan,
    upsert_nmap_override,
)
from .pihole_hourly import export_pihole_hourly_csv
from .router_snmp import (
    format_router_snapshot_json,
    format_router_snapshot_text,
    ingest_router_snmp_events,
    load_router_snapshot,
    run_router_snmp_listener_limited,
)
from .speedtest_runner import run_speedtest_measurement
from .storage import build_report, init_database, load_history_from_db, load_probe_runs_from_db, save_run_record
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


def _refresh_interactive_dashboard_snapshot(config, now: datetime) -> tuple[bool, str]:
    history = load_history_from_db(config, now)
    run_rows = load_probe_runs_from_db(config, now, days=30)
    export_pihole_hourly_csv(config, now, days=30)
    export_nmap_inventory_json(config, now)
    return generate_interactive_dashboard(
        history,
        now,
        config.interactive_dashboard_file,
        config=config,
        run_rows=run_rows,
    )


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
                "title": "Firewall Attack Alert",
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

    history = load_history_from_db(config, run_at)
    run_rows = load_probe_runs_from_db(config, run_at, days=30)
    pihole_hourly_warning = ""
    if config.interactive_dashboard_enabled:
        ok, message = export_pihole_hourly_csv(config, run_at, days=30)
        if not ok:
            pihole_hourly_warning = message
        export_nmap_inventory_json(config, run_at)

    if mode in {"full", "speedtest-only"} and speed_result.ok:
        chart_generator = generate_premium_dashboard if config.dashboard_style == "premium" else generate_chart
        chart_ok, chart_message = chart_generator(history, run_at, config.chart_file, speed_result)
        speed_result.chart_generated = chart_ok
        if not chart_ok:
            speed_result.warnings.append(chart_message)

    if mode in {"full", "speedtest-only"} and config.interactive_dashboard_enabled:
        dashboard_ok, dashboard_message = generate_interactive_dashboard(
            history,
            run_at,
            config.interactive_dashboard_file,
            config=config,
            run_rows=run_rows,
        )
        if not dashboard_ok:
            speed_result.warnings.append(dashboard_message)
        elif pihole_hourly_warning:
            speed_result.warnings.append(pihole_hourly_warning)

    version_line = version_status_line(timeout=config.request_timeout) if mode == "full" else None
    firewall_snapshot = None
    router_snapshot = None
    router_source = (
        f"udp://{config.router_snmp_bind_host}:{config.router_snmp_bind_port}"
        if config.router_snmp_listener_enabled
        else config.router_snmp_log_path
    )
    if config.router_snmp_enabled and config.router_snmp_listener_enabled:
        router_source = f"{router_source} + {config.router_snmp_log_path}"
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
                    nmap_rows, _ = load_dashboard_nmap_inventory(config)
                    firewall_chart_ok, _ = generate_firewall_chart(firewall_snapshot, config.firewall_chart_file, devices=nmap_rows)
                    try:
                        if firewall_chart_ok and Path(config.firewall_chart_file).exists():
                            post_webhook_file(config, alert_payload, config.firewall_chart_file)
                        else:
                            post_webhook_json(config, alert_payload)
                        _write_last_firewall_alert_sent_at(state_file, run_at)
                    except requests.RequestException as exc:
                        raise RuntimeError(f"Discord firewall alert POST failed: {exc}") from exc
    if mode == "full" and (config.router_snmp_enabled or config.router_snmp_listener_enabled):
        ingested_events = 0
        ingest_note = "Router listener mode active; ingest is direct to database." if config.router_snmp_listener_enabled else ""
        if config.router_snmp_enabled:
            ingested_events, ingest_note = ingest_router_snmp_events(
                config.db_path,
                config.router_snmp_log_path,
                config.router_snmp_state_file,
                run_at,
                suppress_missing_note=config.router_snmp_listener_enabled,
            )
        router_snapshot = load_router_snapshot(
            config.db_path,
            enabled=True,
            ingest_source=router_source,
            window_hours=config.router_snmp_window_hours,
            top_n=config.router_snmp_top_n,
            now=run_at,
            ingested_events=ingested_events,
            note=ingest_note or None,
            oid_severity_map=config.router_snmp_oid_severity_map,
        )

    dashboard_summary = build_dashboard_summary(history, run_at, config=config, run_rows=run_rows)
    payload = build_embed(
        config,
        hostname,
        run_at_local,
        history,
        update_result,
        pihole_result,
        speed_result,
        probe_version_line=version_line,
        firewall_snapshot=firewall_snapshot,
        router_snapshot=router_snapshot,
        dashboard_summary=dashboard_summary,
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


def render_firewall_chart(output_path: str | None = None, window_hours: int | None = None) -> str:
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
    now = datetime.now().astimezone()
    if not Path(config.nmap_inventory_json).exists() and Path(config.nmap_inventory_xml).exists():
        export_nmap_inventory_json(config, now)
    nmap_rows, _ = load_dashboard_nmap_inventory(config)
    target_path = output_path or config.firewall_chart_file
    ok, message = generate_firewall_chart(snapshot, target_path, devices=nmap_rows)
    if not ok:
        raise RuntimeError(message)
    return target_path


def render_router_report(window_hours: int | None = None, as_json: bool = False) -> str:
    config = load_config(require_webhook=False)
    now = datetime.now().astimezone()
    router_source = (
        f"udp://{config.router_snmp_bind_host}:{config.router_snmp_bind_port}"
        if config.router_snmp_listener_enabled
        else config.router_snmp_log_path
    )
    if config.router_snmp_enabled and config.router_snmp_listener_enabled:
        router_source = f"{router_source} + {config.router_snmp_log_path}"
    snapshot = load_router_snapshot(
        config.db_path,
        enabled=(config.router_snmp_enabled or config.router_snmp_listener_enabled),
        ingest_source=router_source,
        window_hours=window_hours or config.router_snmp_window_hours,
        top_n=config.router_snmp_top_n,
        now=now,
        oid_severity_map=config.router_snmp_oid_severity_map,
    )
    if as_json:
        return format_router_snapshot_json(snapshot)
    return format_router_snapshot_text(snapshot)


def render_network_diagnosis(as_json: bool = False) -> str:
    config = load_config(require_webhook=False)
    now = datetime.now().astimezone()
    if not Path(config.nmap_inventory_json).exists() and Path(config.nmap_inventory_xml).exists():
        export_nmap_inventory_json(config, now)
    router_source = (
        f"udp://{config.router_snmp_bind_host}:{config.router_snmp_bind_port}"
        if config.router_snmp_listener_enabled
        else config.router_snmp_log_path
    )
    if config.router_snmp_enabled and config.router_snmp_listener_enabled:
        router_source = f"{router_source} + {config.router_snmp_log_path}"
    router_snapshot = load_router_snapshot(
        config.db_path,
        enabled=(config.router_snmp_enabled or config.router_snmp_listener_enabled),
        ingest_source=router_source,
        window_hours=config.router_snmp_window_hours,
        top_n=config.router_snmp_top_n,
        now=now,
        oid_severity_map=config.router_snmp_oid_severity_map,
    )
    event_rows = load_dashboard_events(config)
    nmap_rows, nmap_meta = load_dashboard_nmap_inventory(config)
    diagnosis = build_network_diagnosis(
        event_rows,
        nmap_rows,
        nmap_meta,
        now=now,
        router_snapshot=router_snapshot,
        config=config,
    )
    if as_json:
        return json.dumps(diagnosis, indent=2)

    lines = [
        f"Network diagnosis: {diagnosis['headline']}",
        f"Inventory age: {diagnosis['scanAge']}",
        f"Visible devices: {diagnosis['inventoryDeviceCount']}",
        f"Infrastructure devices: {diagnosis['infrastructureCount']}",
        f"Recent host-missing events: {diagnosis['hostMissingCount']}",
        f"Recent port-closed events: {diagnosis['portClosedCount']}",
        f"Recent linkDown traps: {diagnosis['linkDownCount']}",
        f"Recent router restart traps: {diagnosis['restartCount']}",
    ]
    suspect_devices = diagnosis.get("suspectDevices", [])
    if suspect_devices:
        rendered = ", ".join(
            device.get("name") or device.get("hostname") or device.get("ip") or "unknown"
            for device in suspect_devices
            if isinstance(device, dict)
        )
        lines.append(f"Suspect extender-like devices: {rendered}")
    lines.append("")
    lines.append("Indicators:")
    lines.extend(f"- {item}" for item in diagnosis.get("indicators", []))
    lines.append("")
    lines.append("Recommended actions:")
    lines.extend(f"- {item}" for item in diagnosis.get("recommendations", []))
    return "\n".join(lines)


def run_router_listener() -> int:
    config = load_config(require_webhook=False)
    init_database(config)
    if not config.router_snmp_listener_enabled:
        raise RuntimeError("Router SNMP listener is disabled. Set PI_PROBE_ROUTER_SNMP_LISTENER_ENABLED=true.")
    on_event_inserted = None
    if config.interactive_dashboard_enabled:
        def _refresh_dashboard() -> None:
            now = datetime.now().astimezone()
            _refresh_interactive_dashboard_snapshot(config, now)

        on_event_inserted = _refresh_dashboard
    run_router_snmp_listener_limited(
        config.db_path,
        config.router_snmp_bind_host,
        config.router_snmp_bind_port,
        max_events_per_minute=config.router_snmp_max_events_per_minute,
        max_packet_bytes=config.router_snmp_max_packet_bytes,
        retention_days=config.history_retention_days,
        on_event_inserted=on_event_inserted,
    )
    return 0


def render_dashboard_html(output_path: str | None = None) -> str:
    config = load_config(require_webhook=False)
    now = datetime.now().astimezone()
    history = load_history_from_db(config, now)
    run_rows = load_probe_runs_from_db(config, now, days=30)
    export_pihole_hourly_csv(config, now, days=30)
    export_nmap_inventory_json(config, now)
    target_path = output_path or config.interactive_dashboard_file
    ok, message = generate_interactive_dashboard(history, now, target_path, config=config, run_rows=run_rows)
    if not ok:
        raise RuntimeError(message)
    return message


def run_dashboard_server() -> int:
    config = load_config(require_webhook=False)
    now = datetime.now().astimezone()
    history = load_history_from_db(config, now)
    run_rows = load_probe_runs_from_db(config, now, days=30)
    export_pihole_hourly_csv(config, now, days=30)
    export_nmap_inventory_json(config, now)
    ok, message = generate_interactive_dashboard(
        history,
        now,
        config.interactive_dashboard_file,
        config=config,
        run_rows=run_rows,
    )
    if not ok:
        raise RuntimeError(message)
    print(message)
    return serve_interactive_dashboard(
        config.interactive_dashboard_file,
        config.interactive_dashboard_host,
        config.interactive_dashboard_port,
        tls_enabled=config.interactive_dashboard_tls_enabled,
        tls_cert_file=config.interactive_dashboard_tls_cert_file,
        tls_key_file=config.interactive_dashboard_tls_key_file,
        api_token=config.interactive_dashboard_api_token,
    )


def run_nmap_scan() -> int:
    config = load_config(require_webhook=False)
    now = datetime.now().astimezone()
    ok, message = run_nmap_inventory_scan(config, now)
    if not ok:
        raise RuntimeError(message)
    if config.interactive_dashboard_enabled:
        dashboard_ok, dashboard_message = _refresh_interactive_dashboard_snapshot(config, now)
        if not dashboard_ok:
            raise RuntimeError(dashboard_message)
    print(message)
    return 0


def render_nmap_devices() -> str:
    config = load_config(require_webhook=False)
    return list_nmap_devices(config)


def save_nmap_override(
    *,
    ip: str = "",
    mac: str = "",
    hostname: str = "",
    name: str = "",
    category: str = "",
    hidden: bool | None = None,
    role: str = "",
    location: str = "",
    uplink_ip: str = "",
) -> str:
    config = load_config(require_webhook=False)
    return upsert_nmap_override(
        config,
        ip=ip,
        mac=mac,
        hostname=hostname,
        name=name,
        category=category,
        hidden=hidden,
        role=role,
        location=location,
        uplink_ip=uplink_ip,
    )


def delete_nmap_override(*, ip: str = "", mac: str = "", hostname: str = "") -> str:
    config = load_config(require_webhook=False)
    return remove_nmap_override(config, ip=ip, mac=mac, hostname=hostname)


def _run_optional_command(command: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=6, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output


def render_dashboard_check() -> str:
    config = load_config(require_webhook=False)
    dashboard_path = Path(config.interactive_dashboard_file)
    exists = dashboard_path.exists()
    host = config.interactive_dashboard_host
    port = config.interactive_dashboard_port
    scheme = "https" if config.interactive_dashboard_tls_enabled else "http"

    listening = "unknown"
    ok, ss_output = _run_optional_command(["ss", "-ltn"])
    if ok:
        listening = "yes" if f":{port} " in ss_output or f":{port}\n" in ss_output else "no"

    ufw_state = "unknown"
    ok, ufw_output = _run_optional_command(["ufw", "status"])
    if ok:
        lowered = ufw_output.lower()
        if f"{port}" in ufw_output:
            ufw_state = "configured rule present"
        elif "inactive" in lowered:
            ufw_state = "ufw inactive"
        else:
            ufw_state = "no obvious rule found"

    tailscale_url = "unavailable"
    ok, tailscale_ip = _run_optional_command(["tailscale", "ip", "-4"])
    if ok and tailscale_ip:
        ip = tailscale_ip.splitlines()[0].strip()
        tailscale_url = f"{scheme}://{ip}:{port}/"

    public_dashboard = config.public_dashboard_url or "not set"
    local_host = "127.0.0.1" if host == "0.0.0.0" else host
    lines = [
        f"Dashboard HTML exists: {'yes' if exists else 'no'}",
        f"Dashboard path: {dashboard_path}",
        f"Configured host: {host}",
        f"Configured port: {port}",
        f"Dashboard TLS: {'enabled' if config.interactive_dashboard_tls_enabled else 'disabled'}",
        f"Port listening: {listening}",
        f"UFW status for port: {ufw_state}",
        f"Suggested local URL: {scheme}://{local_host}:{port}/",
        f"Suggested Tailscale URL: {tailscale_url}",
        f"Public dashboard URL: {public_dashboard}",
    ]
    if config.interactive_dashboard_tls_enabled:
        lines.append(f"TLS cert file: {config.interactive_dashboard_tls_cert_file}")
        lines.append(f"TLS key file: {config.interactive_dashboard_tls_key_file}")
    return "\n".join(lines)
