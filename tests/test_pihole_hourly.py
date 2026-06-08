from __future__ import annotations

import csv
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from pi_probe_discord.pihole_hourly import export_pihole_hourly_csv
from tests.test_dashboard import make_config


class PiholeHourlyTests(unittest.TestCase):
    def test_export_pihole_hourly_csv_from_ftl_queries_view(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            with sqlite3.connect(config.pihole_ftl_db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE query_storage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        type INTEGER NOT NULL,
                        status INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        client TEXT NOT NULL,
                        forward TEXT,
                        additional_info BLOB,
                        reply_type INTEGER,
                        reply_time REAL,
                        dnssec INTEGER,
                        regex_id INTEGER
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE VIEW queries AS
                    SELECT timestamp, status FROM query_storage
                    """
                )
                conn.executemany(
                    "INSERT INTO query_storage (timestamp, type, status, domain, client) VALUES (?, ?, ?, ?, ?)",
                    [
                        (int(datetime(2026, 6, 8, 10, 5).timestamp()), 1, 2, "allowed.example", "192.168.1.2"),
                        (int(datetime(2026, 6, 8, 10, 15).timestamp()), 1, 1, "blocked.example", "192.168.1.2"),
                        (int(datetime(2026, 6, 8, 11, 0).timestamp()), 1, 4, "regex-blocked.example", "192.168.1.2"),
                    ],
                )
            ok, _ = export_pihole_hourly_csv(config, datetime(2026, 6, 8, 12, 0), days=2)
            self.assertTrue(ok)
            with open(config.pihole_hourly_csv, encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["dns_queries"], "2")
            self.assertEqual(rows[0]["blocked_queries"], "1")
            self.assertEqual(rows[0]["blocked_percent"], "50.0")
            self.assertEqual(rows[1]["dns_queries"], "1")
            self.assertEqual(rows[1]["blocked_queries"], "1")


if __name__ == "__main__":
    unittest.main()
