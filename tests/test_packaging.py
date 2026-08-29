from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from pi_probe_discord import installer


REPO_ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_nmap_timer_unit_has_persistent_randomized_schedule(self) -> None:
        timer_path = REPO_ROOT / "debian" / "systemd" / "pi-probe-discord-nmap.timer"
        contents = timer_path.read_text(encoding="utf-8")
        self.assertIn("OnBootSec=15min", contents)
        self.assertIn("OnUnitActiveSec=6h", contents)
        self.assertIn("RandomizedDelaySec=10min", contents)
        self.assertIn("Persistent=true", contents)
        self.assertIn("Unit=pi-probe-discord-nmap.service", contents)

    def test_speedtest_timer_runs_hourly_after_completion(self) -> None:
        timer_path = REPO_ROOT / "debian" / "systemd" / "pi-probe-discord-speedtest.timer"
        contents = timer_path.read_text(encoding="utf-8")
        self.assertIn("OnActiveSec=1h", contents)
        self.assertIn("OnUnitInactiveSec=1h", contents)
        self.assertNotIn("RandomizedDelaySec=", contents)

    def test_nmap_service_uses_existing_cli_and_env_file(self) -> None:
        service_path = REPO_ROOT / "debian" / "systemd" / "pi-probe-discord-nmap.service"
        contents = service_path.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", contents)
        self.assertIn("EnvironmentFile=-/etc/pi-probe-discord/pihole-update-discord.env", contents)
        self.assertIn("ExecStart=/usr/bin/pi-probe-discord nmap-scan", contents)
        self.assertIn("ReadWritePaths=/var/lib/pi-probe-discord", contents)

    def test_postinst_generates_nmap_timer_override_from_env(self) -> None:
        postinst_path = REPO_ROOT / "debian" / "postinst"
        contents = postinst_path.read_text(encoding="utf-8")
        self.assertIn("PI_PROBE_NMAP_SCAN_MINUTES", contents)
        self.assertIn('if [ "$minutes" -lt 5 ]; then', contents)
        self.assertIn('OnUnitActiveSec=${minutes}min', contents)
        self.assertIn("restart_if_enabled pi-probe-discord-nmap.timer", contents)
        self.assertNotIn("enable_if_file_exists", contents)

    def test_package_upgrade_does_not_enable_user_disabled_timers(self) -> None:
        postinst_path = REPO_ROOT / "debian" / "postinst"
        contents = postinst_path.read_text(encoding="utf-8")
        self.assertNotIn("systemctl enable --now pi-probe-discord-speedtest.timer", contents)
        self.assertNotIn("systemctl enable --now pi-probe-discord-full.timer", contents)
        self.assertNotIn("systemctl enable --now pi-probe-discord-nmap.timer", contents)

    def test_installer_template_documents_new_dashboard_and_nmap_settings(self) -> None:
        env_template = installer.ENV_TEMPLATE
        self.assertIn('PI_PROBE_DASHBOARD_REFRESH_SECONDS="60"', env_template)
        self.assertIn('PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN=""', env_template)
        self.assertIn('PI_PROBE_NMAP_SCAN_MINUTES="360"', env_template)

    def test_installer_backs_up_existing_config_with_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "pihole-update-discord.env"
            config_path.write_text('WEBHOOK_URL="existing"\n', encoding="utf-8")
            backup_path = installer._backup_existing_config(config_path)
            self.assertEqual(backup_path.read_text(encoding="utf-8"), 'WEBHOOK_URL="existing"\n')
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
