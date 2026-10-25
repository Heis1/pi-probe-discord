import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pi_probe_discord.wan_bandwidth import collect_wan_bandwidth


class WanBandwidthTests(unittest.TestCase):
    def _config(self, root: Path):
        return SimpleNamespace(
            wan_bandwidth_enabled=True, wan_bandwidth_interface="wan1",
            wan_bandwidth_state_json=str(root / "wan" / "latest.json"),
            fortigate_secret_file=str(root / "fortigate.env"), db_path=str(root / "probe.db"),
            wan_bandwidth_raw_retention_hours=24, wan_bandwidth_aggregate_retention_days=7,
        )

    def test_first_sample_waits_for_baseline_then_calculates_rate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = self._config(root)
            with patch("pi_probe_discord.wan_bandwidth._run", side_effect=[(True, ['.1.3.6.1.2.1.31.1.1.1.1.7 "wan1"'], ''), (True, ['100', '200', '1000'], ''), (True, ['.1.3.6.1.2.1.31.1.1.1.1.7 "wan1"'], ''), (True, ['1100', '700', '1010'], '')]):
                first = collect_wan_bandwidth(config, monotonic=lambda: 10.0, now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
                second = collect_wan_bandwidth(config, monotonic=lambda: 15.0, now=lambda: datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc))
            self.assertFalse(first["available"])
            self.assertTrue(second["available"])
            self.assertAlmostEqual(second["downloadMbps"], 0.0016)
            self.assertAlmostEqual(second["uploadMbps"], 0.0008)

    def test_counter_reset_never_returns_negative_rate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = self._config(root); state = Path(config.wan_bandwidth_state_json); state.parent.mkdir(parents=True)
            state.write_text(json.dumps({"interfaceIndex": 7, "uptime": 1000, "counterIn": 1000, "counterOut": 1000, "monotonic": 1.0}))
            with patch("pi_probe_discord.wan_bandwidth._run", side_effect=[(True, ['.1.3.6.1.2.1.31.1.1.1.1.7 "wan1"'], ''), (True, ['10', '20', '10'], '')]):
                result = collect_wan_bandwidth(config, monotonic=lambda: 6.0, now=lambda: datetime.now(timezone.utc))
            self.assertFalse(result["available"])
            self.assertIsNone(result["downloadMbps"])
