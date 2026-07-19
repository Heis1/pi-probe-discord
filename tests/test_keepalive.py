from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pi_probe_discord.keepalive import load_keepalive_state, run_keepalive


class KeepaliveTests(unittest.TestCase):
    def test_run_keepalive_records_each_configured_router(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "latest.json"
            config = SimpleNamespace(
                keepalive_enabled=True,
                keepalive_devices_json='[{"name":"VR2100 Upstairs","host":"192.168.1.1"}]',
                keepalive_state_json=str(state_path),
                keepalive_timeout_seconds=1,
            )
            completed = SimpleNamespace(returncode=0, stdout="64 bytes time=1.23 ms", stderr="")
            with patch("pi_probe_discord.keepalive.subprocess.run", return_value=completed):
                state = run_keepalive(config)
            self.assertTrue(state["devices"][0]["up"])
            self.assertEqual(state["devices"][0]["latencyMs"], 1.23)
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8"))["devices"][0]["name"], "VR2100 Upstairs")

    def test_load_keepalive_state_returns_empty_before_first_check(self) -> None:
        config = SimpleNamespace(keepalive_enabled=True, keepalive_state_json="/does/not/exist")
        self.assertEqual(load_keepalive_state(config)["devices"], [])


if __name__ == "__main__":
    unittest.main()
