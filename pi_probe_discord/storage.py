from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import AppConfig, RunRecord


_database_init_lock = threading.Lock()
_initialized_databases: set[str] = set()


def compact_text(value: str, limit: int) -> str:
    cleaned = " ".join((value or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def init_database(config: AppConfig) -> None:
    db_path = Path(config.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_key = str(db_path.resolve())
    if database_key in _initialized_databases:
        return

    # Schema setup obtains a write lock.  It must not run for every dashboard
    # request while the WAN collector is writing a sample.
    with _database_init_lock:
        if database_key in _initialized_databases:
            return
        conn = sqlite3.connect(db_path, timeout=15)
        conn.execute("PRAGMA busy_timeout = 15000")
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS router_snmp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                trap_oid TEXT NOT NULL,
                summary TEXT NOT NULL,
                raw_line TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_runs_recorded_at ON probe_runs(recorded_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_router_snmp_events_recorded_at ON router_snmp_events(recorded_at)"
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wan_bandwidth_samples (
                recorded_at TEXT PRIMARY KEY, interface_index INTEGER NOT NULL,
                download_mbps REAL NOT NULL, upload_mbps REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wan_bandwidth_minute (
                bucket_at TEXT PRIMARY KEY, interface_index INTEGER NOT NULL,
                avg_download_mbps REAL NOT NULL, avg_upload_mbps REAL NOT NULL,
                peak_download_mbps REAL NOT NULL, peak_upload_mbps REAL NOT NULL,
                sample_count INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wan_samples_recorded_at ON wan_bandwidth_samples(recorded_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wan_bandwidth_talkers (
                recorded_at TEXT NOT NULL, source_ip TEXT NOT NULL,
                source_name TEXT NOT NULL, byte_count INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wan_talkers_recorded_at ON wan_bandwidth_talkers(recorded_at)")
        _initialized_databases.add(database_key)
        conn.close()


def save_wan_bandwidth_sample(config: AppConfig, recorded_at: datetime, interface_index: int, download_mbps: float, upload_mbps: float) -> None:
    """Persist a measured rate and compact old raw samples into minute buckets."""
    init_database(config)
    stamp = recorded_at.isoformat()
    raw_cutoff = (recorded_at - timedelta(hours=config.wan_bandwidth_raw_retention_hours)).isoformat()
    aggregate_cutoff = (recorded_at - timedelta(days=config.wan_bandwidth_aggregate_retention_days)).isoformat()
    bucket = recorded_at.replace(second=0, microsecond=0).isoformat()
    with sqlite3.connect(config.db_path) as conn:
        conn.execute("INSERT OR REPLACE INTO wan_bandwidth_samples VALUES (?, ?, ?, ?)", (stamp, interface_index, download_mbps, upload_mbps))
        conn.execute("""
            INSERT INTO wan_bandwidth_minute (bucket_at, interface_index, avg_download_mbps, avg_upload_mbps, peak_download_mbps, peak_upload_mbps, sample_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(bucket_at) DO UPDATE SET
              interface_index=excluded.interface_index,
              avg_download_mbps=((wan_bandwidth_minute.avg_download_mbps * wan_bandwidth_minute.sample_count) + excluded.avg_download_mbps) / (wan_bandwidth_minute.sample_count + 1),
              avg_upload_mbps=((wan_bandwidth_minute.avg_upload_mbps * wan_bandwidth_minute.sample_count) + excluded.avg_upload_mbps) / (wan_bandwidth_minute.sample_count + 1),
              peak_download_mbps=MAX(wan_bandwidth_minute.peak_download_mbps, excluded.peak_download_mbps),
              peak_upload_mbps=MAX(wan_bandwidth_minute.peak_upload_mbps, excluded.peak_upload_mbps),
              sample_count=wan_bandwidth_minute.sample_count + 1
        """, (bucket, interface_index, download_mbps, upload_mbps, download_mbps, upload_mbps))
        conn.execute("DELETE FROM wan_bandwidth_samples WHERE recorded_at < ?", (raw_cutoff,))
        conn.execute("DELETE FROM wan_bandwidth_minute WHERE bucket_at < ?", (aggregate_cutoff,))


def save_wan_talker(config: AppConfig, recorded_at: datetime, source_ip: str, source_name: str, byte_count: int) -> None:
    """Persist FortiGate traffic attribution independently of log rotation."""
    if not source_ip:
        return
    init_database(config)
    cutoff = (recorded_at - timedelta(days=config.wan_bandwidth_aggregate_retention_days)).isoformat()
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            "INSERT INTO wan_bandwidth_talkers VALUES (?, ?, ?, ?)",
            (recorded_at.isoformat(), source_ip, source_name, max(0, int(byte_count))),
        )
        conn.execute("DELETE FROM wan_bandwidth_talkers WHERE recorded_at < ?", (cutoff,))


def load_wan_talkers(config: AppConfig, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Load retained traffic events for assigning to dashboard sample points."""
    init_database(config)
    with sqlite3.connect(config.db_path) as conn:
        rows = conn.execute(
            "SELECT recorded_at, source_ip, source_name, byte_count FROM wan_bandwidth_talkers WHERE recorded_at >= ? AND recorded_at <= ? ORDER BY recorded_at",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
    return [{"at": row[0], "ip": row[1], "name": row[2], "bytes": row[3]} for row in rows]


def load_wan_bandwidth_history(config: AppConfig, period_seconds: int, now: datetime) -> list[dict[str, Any]]:
    init_database(config)
    cutoff = now - timedelta(seconds=max(60, period_seconds))
    raw_cutoff = now - timedelta(hours=config.wan_bandwidth_raw_retention_hours)
    points: list[dict[str, Any]] = []
    with sqlite3.connect(config.db_path) as conn:
        if cutoff < raw_cutoff:
            rows = conn.execute("SELECT bucket_at, avg_download_mbps, avg_upload_mbps FROM wan_bandwidth_minute WHERE bucket_at >= ? AND bucket_at < ? ORDER BY bucket_at", (cutoff.isoformat(), raw_cutoff.isoformat())).fetchall()
            points.extend({"at": row[0], "downloadMbps": row[1], "uploadMbps": row[2], "aggregate": True} for row in rows)
        rows = conn.execute("SELECT recorded_at, download_mbps, upload_mbps FROM wan_bandwidth_samples WHERE recorded_at >= ? ORDER BY recorded_at", (max(cutoff, raw_cutoff).isoformat(),)).fetchall()
        points.extend({"at": row[0], "downloadMbps": row[1], "uploadMbps": row[2], "aggregate": False} for row in rows)
    return points


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
        conn.execute("DELETE FROM router_snmp_events WHERE recorded_at < ?", (cutoff,))
        conn.execute("PRAGMA incremental_vacuum")


def load_history_from_db(config: AppConfig, now: datetime) -> dict[str, list[dict[str, Any]]]:
    init_database(config)
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


def load_probe_runs_from_db(config: AppConfig, now: datetime, days: int = 30) -> list[dict[str, Any]]:
    cutoff = (now - timedelta(days=days)).isoformat()
    with sqlite3.connect(config.db_path) as conn:
        rows = conn.execute(
            """
            SELECT recorded_at, hostname, speed_ok, speed_summary, download_mbps, upload_mbps, ping_ms, speed_warnings
            FROM probe_runs
            WHERE recorded_at >= ?
            ORDER BY recorded_at ASC
            """,
            (cutoff,),
        ).fetchall()

    results: list[dict[str, Any]] = []
    for recorded_at, hostname, speed_ok, speed_summary, download_mbps, upload_mbps, ping_ms, speed_warnings in rows:
        results.append(
            {
                "recorded_at": recorded_at,
                "hostname": hostname,
                "speed_ok": bool(speed_ok),
                "speed_summary": speed_summary or "",
                "download_mbps": float(download_mbps) if isinstance(download_mbps, (int, float)) else None,
                "upload_mbps": float(upload_mbps) if isinstance(upload_mbps, (int, float)) else None,
                "ping_ms": float(ping_ms) if isinstance(ping_ms, (int, float)) else None,
                "speed_warnings": speed_warnings or "",
            }
        )
    return results


def build_report(config: AppConfig, days: int) -> str:
    cutoff = (datetime.now().astimezone() - timedelta(days=days)).isoformat()

    try:
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
    except sqlite3.OperationalError:
        return f"No stored probe data for the last {days} day(s)."

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
