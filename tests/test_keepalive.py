from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pi_probe_discord.keepalive import load_keepalive_state, run_keepalive, set_device_ping_enabled


class KeepaliveTests(unittest.TestCase):
    def test_run_keepalive_records_each_configured_router(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "latest.json"
            config = SimpleNamespace(
                keepalive_enabled=True,
                keepalive_devices_json='[{"name":"Test Router","host":"192.168.1.1"}]',
                keepalive_state_json=str(state_path),
                keepalive_timeout_seconds=1,
            )
            completed = SimpleNamespace(returncode=0, stdout="64 bytes time=1.23 ms", stderr="")
            with patch("pi_probe_discord.keepalive.subprocess.run", return_value=completed):
                state = run_keepalive(config)
            self.assertTrue(state["devices"][0]["up"])
            self.assertEqual(state["devices"][0]["latencyMs"], 1.23)
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8"))["devices"][0]["name"], "Test Router")

    def test_load_keepalive_state_returns_empty_before_first_check(self) -> None:
        config = SimpleNamespace(keepalive_enabled=True, keepalive_state_json="/does/not/exist")
        self.assertEqual(load_keepalive_state(config)["devices"], [])

    def test_disabled_device_is_retained_but_not_pinged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "latest.json"
            config = SimpleNamespace(
                keepalive_enabled=True,
                keepalive_devices_json='[{"name":"Test Router","host":"192.168.1.1"}]',
                keepalive_state_json=str(state_path),
                keepalive_timeout_seconds=1,
            )
            set_device_ping_enabled(config, "192.168.1.1", False)
            with patch("pi_probe_discord.keepalive.subprocess.run") as command:
                state = run_keepalive(config)
            command.assert_not_called()
            self.assertFalse(state["devices"][0]["pingEnabled"])
            self.assertIsNone(state["devices"][0]["up"])


if __name__ == "__main__":
    unittest.main()
