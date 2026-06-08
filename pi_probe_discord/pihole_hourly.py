from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from .models import AppConfig

_BLOCKED_STATUSES = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)


def export_pihole_hourly_csv(config: AppConfig, now: datetime, days: int = 30) -> tuple[bool, str]:
    ftl_db = Path(config.pihole_ftl_db_path)
    output = Path(config.pihole_hourly_csv)
    if not ftl_db.exists():
        return False, f"Pi-hole FTL DB not found: {ftl_db}"

    cutoff = int((now - timedelta(days=max(1, days))).timestamp())
    placeholders = ",".join(str(value) for value in _BLOCKED_STATUSES)
    query = f"""
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp, 'unixepoch', 'localtime') AS hour_bucket,
            COUNT(*) AS dns_queries,
            SUM(CASE WHEN status IN ({placeholders}) THEN 1 ELSE 0 END) AS blocked_queries
        FROM queries
        WHERE timestamp >= ?
        GROUP BY hour_bucket
        ORDER BY hour_bucket ASC
    """
    try:
        with sqlite3.connect(ftl_db) as conn:
            rows = conn.execute(query, (cutoff,)).fetchall()
    except sqlite3.Error as exc:
        return False, f"Pi-hole query DB read failed: {exc}"

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["datetime", "dns_queries", "blocked_queries", "blocked_percent"])
        for hour_bucket, dns_queries, blocked_queries in rows:
            total = int(dns_queries or 0)
            blocked = int(blocked_queries or 0)
            blocked_percent = round((blocked / total) * 100.0, 2) if total else 0.0
            writer.writerow([hour_bucket, total, blocked, blocked_percent])

    return True, f"Pi-hole hourly CSV written to {output}"
