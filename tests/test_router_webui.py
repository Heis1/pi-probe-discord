from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from pi_probe_discord.router_webui import collect_router_webui_snapshot
from tests.test_dashboard import make_config


class RouterWebUiTests(unittest.TestCase):
    def test_collect_router_webui_snapshot_uses_pinned_certificate_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.router_webui_enabled = True
            config.router_webui_url = "https://192.168.1.1"
            config.router_webui_ca_file = str(Path(tmp) / "router-webui-ca.pem")
            Path(config.router_webui_ca_file).write_text("dummy", encoding="utf-8")

            with patch("pi_probe_discord.router_webui.load_router_webui_secrets", return_value={"username": "admin", "password": "secret"}), \
                 patch("pi_probe_discord.router_webui._load_pinned_certificate_fingerprint", return_value="abc123"), \
                 patch("pi_probe_discord.router_webui._fetch_peer_certificate_fingerprint", return_value="abc123"), \
                 patch("pi_probe_discord.router_webui._RouterWebUiSession.login"), \
                 patch("pi_probe_discord.router_webui._RouterWebUiSession.call") as mock_call:
                mock_call.side_effect = [
                    {"modelName": "Archer VR2100", "description": "Router"},
                    {"userName": "admin"},
                    [{"IPAddress": "192.168.1.100", "MACAddress": "02:00:00:00:00:0A", "hostName": "test-host", "active": "1"}],
                ]
                snapshot = collect_router_webui_snapshot(config, datetime(2026, 7, 18, 18, 0, 0).isoformat())

            self.assertTrue(snapshot["available"])
            self.assertEqual(snapshot["hostTable"][0]["hostName"], "test-host")

    def test_router_webui_session_mounts_pinned_fingerprint_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.router_webui_enabled = True
            config.router_webui_url = "https://192.168.1.1"
            config.router_webui_ca_file = str(Path(tmp) / "router-webui-ca.pem")
            Path(config.router_webui_ca_file).write_text("dummy", encoding="utf-8")
            with patch("pi_probe_discord.router_webui.load_router_webui_secrets", return_value={"username": "admin", "password": "secret"}), \
                 patch("pi_probe_discord.router_webui._load_pinned_certificate_fingerprint", return_value="abc123"), \
                 patch("pi_probe_discord.router_webui._fetch_peer_certificate_fingerprint", return_value="abc123"), \
                 patch("pi_probe_discord.router_webui._RouterWebUiSession.login"), \
                 patch("pi_probe_discord.router_webui._RouterWebUiSession.call", side_effect=[
                     {"modelName": "Archer VR2100", "description": "Router"},
                     {"userName": "admin"},
                     [],
                ]), \
                 patch("pi_probe_discord.router_webui.requests.Session") as mock_session_factory:
                mock_session = MagicMock()
                mock_session_factory.return_value = mock_session
                collect_router_webui_snapshot(config, datetime(2026, 7, 18, 18, 0, 0).isoformat())
                self.assertFalse(mock_session.verify)
                mock_session.mount.assert_called_once()
                mount_prefix, adapter = mock_session.mount.call_args[0]
                self.assertEqual(mount_prefix, "https://192.168.1.1")
                self.assertEqual(adapter._fingerprint, "abc123")


if __name__ == "__main__":
    unittest.main()
