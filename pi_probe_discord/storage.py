from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import AppConfig, RunRecord


def compact_text(value: str, limit: int) -> str:
    cleaned = " ".join((value or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def init_database(config: AppConfig) -> None:
    db_path = Path(config.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS probe_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                hostname TEXT NOT NULL,
                update_ok INTEGER NOT NULL,
                update_summary TEXT NOT NULL,
                update_error TEXT NOT NULL,
                pihole_service_status TEXT NOT NULL,
                pihole_blocking_status TEXT NOT NULL,
                pihole_gravity_age TEXT NOT NULL,
                pihole_blocklist_count TEXT NOT NULL,
                pihole_warnings TEXT NOT NULL,
                speed_ok INTEGER NOT NULL,
                speed_summary TEXT NOT NULL,
                download_mbps REAL,
                upload_mbps REAL,
                ping_ms REAL,
                speed_warnings TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_runs_recorded_at ON probe_runs(recorded_at)")


def save_run_record(config: AppConfig, record: RunRecord) -> None:
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            INSERT INTO probe_runs (
                recorded_at, hostname, update_ok, update_summary, update_error,
                pihole_service_status, pihole_blocking_status, pihole_gravity_age,
                pihole_blocklist_count, pihole_warnings, speed_ok, speed_summary,
                download_mbps, upload_mbps, ping_ms, speed_warnings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.recorded_at.isoformat(),
                record.hostname,
                int(record.update_ok),
                compact_text(record.update_summary, config.max_text_field_length),
                compact_text(record.update_error, config.max_text_field_length),
                record.pihole_service_status,
                record.pihole_blocking_status,
                compact_text(record.pihole_gravity_age, 256),
                compact_text(record.pihole_blocklist_count, 256),
                compact_text(record.pihole_warnings, config.max_text_field_length),
                int(record.speed_ok),
                compact_text(record.speed_summary, config.max_text_field_length),
                record.download_mbps,
                record.upload_mbps,
                record.ping_ms,
                compact_text(record.speed_warnings, config.max_text_field_length),
            ),
        )
        cutoff = (record.recorded_at - timedelta(days=config.history_retention_days)).isoformat()
        conn.execute("DELETE FROM probe_runs WHERE recorded_at < ?", (cutoff,))
        conn.execute("PRAGMA incremental_vacuum")


def load_history_from_db(config: AppConfig, now: datetime) -> dict[str, list[dict[str, Any]]]:
    history = {"download": [], "upload": [], "ping": []}
    cutoff = (now - timedelta(days=config.history_retention_days)).isoformat()

    with sqlite3.connect(config.db_path) as conn:
        rows = conn.execute(
            """
            SELECT recorded_at, download_mbps, upload_mbps, ping_ms
            FROM probe_runs
            WHERE recorded_at >= ?
            ORDER BY recorded_at ASC
            """,
            (cutoff,),
        ).fetchall()

    for recorded_at, download_mbps, upload_mbps, ping_ms in rows:
        if isinstance(download_mbps, (int, float)):
            history["download"].append({"x": recorded_at, "y": float(download_mbps)})
        if isinstance(upload_mbps, (int, float)):
            history["upload"].append({"x": recorded_at, "y": float(upload_mbps)})
        if isinstance(ping_ms, (int, float)):
            history["ping"].append({"x": recorded_at, "y": float(ping_ms)})
    return history


def build_report(config: AppConfig, days: int) -> str:
    cutoff = (datetime.now().astimezone() - timedelta(days=days)).isoformat()

    with sqlite3.connect(config.db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN update_ok = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN speed_ok = 1 THEN 1 ELSE 0 END),
                AVG(download_mbps),
                AVG(upload_mbps),
                AVG(ping_ms),
                MAX(recorded_at)
            FROM probe_runs
            WHERE recorded_at >= ?
            """,
            (cutoff,),
        ).fetchone()

    if not rows or not rows[0]:
        return f"No stored probe data for the last {days} day(s)."

    total_runs, update_ok_runs, speed_ok_runs, avg_down, avg_up, avg_ping, latest = rows
    lines = [
        f"Report window: last {days} day(s)",
        f"Database: {config.db_path}",
        f"Runs stored: {total_runs}",
        f"Successful updates: {update_ok_runs}/{total_runs}",
        f"Successful speed tests: {speed_ok_runs}/{total_runs}",
        f"Average download: {avg_down:.2f} Mbps" if avg_down is not None else "Average download: n/a",
        f"Average upload: {avg_up:.2f} Mbps" if avg_up is not None else "Average upload: n/a",
        f"Average ping: {avg_ping:.2f} ms" if avg_ping is not None else "Average ping: n/a",
        f"Latest run: {latest}",
    ]
    return "\n".join(lines)

