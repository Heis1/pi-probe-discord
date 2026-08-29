from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pi_probe_discord.app import _reporting_enabled_for_mode, run_mode, run_router_listener
from pi_probe_discord.models import SpeedResult
from tests.test_dashboard import make_config


class AppTests(unittest.TestCase):
    def test_report_modes_can_limit_discord_to_speedtests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.discord_report_modes = ["speedtest-only"]

        self.assertTrue(_reporting_enabled_for_mode(config, "speedtest-only"))
        self.assertFalse(_reporting_enabled_for_mode(config, "full"))
        self.assertFalse(_reporting_enabled_for_mode(config, "firewall"))

    def test_router_listener_exits_cleanly_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.router_snmp_listener_enabled = False
            with patch("pi_probe_discord.app.load_config", return_value=config), \
                 patch("pi_probe_discord.app.init_database") as init_database:
                result = run_router_listener()

        self.assertEqual(result, 0)
        init_database.assert_not_called()

    def test_speedtest_only_runs_without_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.webhook_url = ""
            config.firewall_alert_enabled = False

            with patch("pi_probe_discord.app.load_config", return_value=config), \
                 patch("pi_probe_discord.app.init_database"), \
                 patch("pi_probe_discord.app.save_run_record") as save_run_record, \
                 patch("pi_probe_discord.app.load_history_from_db", return_value={"download": [], "upload": [], "ping": []}), \
                 patch("pi_probe_discord.app.load_probe_runs_from_db", return_value=[]), \
                 patch("pi_probe_discord.app.export_pihole_hourly_csv", return_value=(True, "ok")), \
                 patch("pi_probe_discord.app.export_nmap_inventory_json"), \
                 patch("pi_probe_discord.app.run_speedtest_measurement", return_value=SpeedResult(ok=True, summary="ok", download_mbps=123.4, upload_mbps=45.6, ping_ms=7.8)), \
                 patch("pi_probe_discord.app.generate_premium_dashboard", return_value=(True, "chart ok")), \
                 patch("pi_probe_discord.app.generate_interactive_dashboard", return_value=(True, "dashboard ok")), \
                 patch("pi_probe_discord.app.version_status_line", return_value="version ok"), \
                 patch("pi_probe_discord.app.build_embed", return_value={"embeds": []}), \
                 patch("pi_probe_discord.app.post_webhook_json") as post_webhook_json, \
                 patch("pi_probe_discord.app.post_webhook_file") as post_webhook_file:
                result = run_mode("speedtest-only")

            self.assertEqual(result, 0)
            save_run_record.assert_called_once()
            post_webhook_json.assert_not_called()
            post_webhook_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
