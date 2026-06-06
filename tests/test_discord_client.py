from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pi_probe_discord.discord_client import build_embed
from pi_probe_discord.models import AppConfig, PiholeResult, SpeedResult, UpdateResult


def make_config(base_dir: Path) -> AppConfig:
    return AppConfig(
        webhook_url="https://discord.invalid/webhook",
        config_file=str(base_dir / "env"),
        log_file=str(base_dir / "probe.log"),
        chart_file=str(base_dir / "speed_chart.png"),
        firewall_chart_file=str(base_dir / "firewall.png"),
        dashboard_style="premium",
        interactive_dashboard_enabled=True,
        interactive_dashboard_file=str(base_dir / "dashboard" / "index.html"),
        interactive_dashboard_host="127.0.0.1",
        interactive_dashboard_port=8088,
        public_dashboard_url="https://example.com/dashboard",
        dashboard_link_label="Open Interactive Dashboard",
        outage_download_mbps=50.0,
        degraded_download_mbps=250.0,
        high_ping_ms=20.0,
        failed_test_is_outage=True,
        heatmap_good_mbps=320.0,
        heatmap_warn_mbps=250.0,
        router_events_csv=str(base_dir / "events" / "router_events.csv"),
        router_events_json=str(base_dir / "events" / "router_events.json"),
        pihole_hourly_csv=str(base_dir / "pihole" / "pihole_hourly.csv"),
        db_path=str(base_dir / "probe.db"),
        history_retention_days=365,
        request_timeout=30,
        max_text_field_length=1200,
        speedtest_schedule_minutes=60,
        full_report_schedule="03:30",
        firewall_enabled=False,
        firewall_window_hours=24,
        firewall_top_n=5,
        firewall_noisy_source_threshold=10,
        firewall_include_allow=False,
        firewall_log_paths=[],
        firewall_alert_enabled=False,
        firewall_alert_min_blocks=80,
        firewall_alert_min_ssh_attempts=20,
        firewall_alert_min_noisy_sources=2,
        firewall_alert_cooldown_minutes=60,
        firewall_alert_state_file=str(base_dir / "firewall_state.json"),
        router_snmp_enabled=False,
        router_snmp_log_path=str(base_dir / "snmp.log"),
        router_snmp_state_file=str(base_dir / "snmp_state.json"),
        router_snmp_window_hours=24,
        router_snmp_top_n=5,
        router_snmp_listener_enabled=False,
        router_snmp_bind_host="0.0.0.0",
        router_snmp_bind_port=9162,
        router_snmp_oid_severity_map={},
    )


class DiscordClientTests(unittest.TestCase):
    def test_build_embed_includes_dashboard_link_and_summary(self) -> None:
        config = make_config(Path(tempfile.mkdtemp()))
        payload = build_embed(
            config=config,
            hostname="probe-host",
            run_at_local="2026-06-06 12:00:00 ACST",
            history={
                "download": [{"x": "2026-06-06T12:00:00", "y": 300.0}],
                "upload": [{"x": "2026-06-06T12:00:00", "y": 45.0}],
                "ping": [{"x": "2026-06-06T12:00:00", "y": 4.0}],
            },
            update_result=UpdateResult(ok=True, summary="ok"),
            pihole_result=PiholeResult(service_status="running", blocking_status="enabled", gravity_age="fresh", blocklist_count="123", update_status="ok"),
            speed_result=SpeedResult(ok=True, summary="Download 300 Mbps | Upload 45 Mbps | Ping 4 ms", download_mbps=300.0, upload_mbps=45.0, ping_ms=4.0),
            dashboard_summary={
                "stats": {
                    "medianDown": 300.0,
                    "avgUp": 45.0,
                    "avgPing": 4.0,
                    "p05": 250.0,
                    "pctThreshold": 92.0,
                    "thresholdMbps": 250.0,
                    "outageCount": 1,
                    "failedCount": 0,
                    "degradedCount": 2,
                    "publicDashboardUrl": "https://example.com/dashboard",
                },
                "score": {"total": 93.5},
            },
        )
        embed = payload["embeds"][0]
        self.assertEqual(embed["url"], "https://example.com/dashboard")
        field_names = {field["name"] for field in embed["fields"]}
        self.assertIn("Dashboard Summary", field_names)
        self.assertIn("Reliability Snapshot", field_names)
        self.assertIn("Open Interactive Dashboard", field_names)


if __name__ == "__main__":
    unittest.main()
