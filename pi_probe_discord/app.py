from __future__ import annotations

import socket
from datetime import datetime
from pathlib import Path

import requests

from .charts import generate_chart
from .config import load_config
from .discord_client import build_embed, post_webhook_file, post_webhook_json
from .models import PiholeResult, RunRecord, SpeedResult, UpdateResult
from .speedtest_runner import run_speedtest_measurement
from .storage import build_report, init_database, load_history_from_db, save_run_record
from .system_checks import collect_pihole_info, run_updates
from .version_check import version_status_line


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
    payload = build_embed(config, hostname, run_at_local, history, update_result, pihole_result, speed_result, version_line)
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
