from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pi_probe_discord.config import load_config, load_router_webui_secrets


class ConfigTests(unittest.TestCase):
    def test_load_router_webui_secrets_requires_root_owned_mode_600_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env_file = base / "pihole-update-discord.env"
            secret_file = base / "router-webui.env"
            env_file.write_text(
                "\n".join(
                    [
                        'WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"',
                        'PI_PROBE_ROUTER_WEBUI_ENABLED="true"',
                        f'PI_PROBE_ROUTER_WEBUI_SECRET_FILE="{secret_file}"',
                    ]
                ),
                encoding="utf-8",
            )
            secret_file.write_text(
                "\n".join(
                    [
                        'PI_PROBE_ROUTER_WEBUI_USERNAME="admin"',
                        'PI_PROBE_ROUTER_WEBUI_PASSWORD="secret"',
                    ]
                ),
                encoding="utf-8",
            )
            os.chmod(secret_file, 0o644)
            os.environ["CONFIG_FILE"] = str(env_file)
            try:
                config = load_config(require_webhook=False)
                fake_stat = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)
                with patch("pathlib.Path.stat", return_value=fake_stat):
                    with self.assertRaisesRegex(RuntimeError, "mode 600"):
                        load_router_webui_secrets(config)
            finally:
                os.environ.pop("CONFIG_FILE", None)

    def test_load_router_webui_secrets_reads_root_only_secret_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env_file = base / "pihole-update-discord.env"
            secret_file = base / "router-webui.env"
            env_file.write_text(
                "\n".join(
                    [
                        'WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"',
                        'PI_PROBE_ROUTER_WEBUI_ENABLED="true"',
                        f'PI_PROBE_ROUTER_WEBUI_SECRET_FILE="{secret_file}"',
                    ]
                ),
                encoding="utf-8",
            )
            secret_file.write_text(
                "\n".join(
                    [
                        'PI_PROBE_ROUTER_WEBUI_USERNAME="admin"',
                        'PI_PROBE_ROUTER_WEBUI_PASSWORD="secret"',
                    ]
                ),
                encoding="utf-8",
            )
            os.chmod(secret_file, stat.S_IRUSR | stat.S_IWUSR)
            os.environ["CONFIG_FILE"] = str(env_file)
            try:
                config = load_config(require_webhook=False)
                fake_stat = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
                with patch("pathlib.Path.stat", return_value=fake_stat):
                    secrets = load_router_webui_secrets(config)
            finally:
                os.environ.pop("CONFIG_FILE", None)
            self.assertEqual(secrets["username"], "admin")
            self.assertEqual(secrets["password"], "secret")

    def test_load_config_reads_router_webui_ca_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env_file = base / "pihole-update-discord.env"
            ca_file = base / "router-webui-ca.pem"
            env_file.write_text(
                "\n".join(
                    [
                        'WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"',
                        'PI_PROBE_ROUTER_WEBUI_ENABLED="true"',
                        f'PI_PROBE_ROUTER_WEBUI_CA_FILE="{ca_file}"',
                    ]
                ),
                encoding="utf-8",
            )
            os.environ["CONFIG_FILE"] = str(env_file)
            try:
                config = load_config(require_webhook=False)
            finally:
                os.environ.pop("CONFIG_FILE", None)
            self.assertEqual(config.router_webui_ca_file, str(ca_file))


if __name__ == "__main__":
    unittest.main()
