from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pi_probe_discord.fortigate import collect_fortigate_snapshot, load_fortigate_state


class FortigateTests(unittest.TestCase):
    def test_collects_monitor_metrics_and_persists_safe_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            secret_file = base / "fortigate.env"
            state_file = base / "fortigate" / "latest.json"
            secret_file.write_text('PI_PROBE_FORTIGATE_API_TOKEN="secret-token"\n', encoding="utf-8")
            config = SimpleNamespace(
                fortigate_enabled=True,
                fortigate_url="https://10.10.10.1",
                fortigate_vdom="root",
                fortigate_secret_file=str(secret_file),
                fortigate_ca_file="",
                fortigate_state_json=str(state_file),
                fortigate_timeout_seconds=8,
                fortigate_tls_verify=False,
            )
            session = MagicMock()
            responses = [
                {"results": {"hostname": "fortiwifi", "version": "v7.0", "serial": "FGT30E"}},
                {"results": {"cpu": [{"current": 12.5}]}},
                {"results": {"mem": [{"current": 61}]}},
                {"results": {"session": [{"current": 42}]}},
            ]
            session.get.side_effect = [
                MagicMock(status_code=200, json=MagicMock(return_value=response))
                for response in responses
            ]
            fake_stat = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
            with patch("pathlib.Path.stat", return_value=fake_stat), patch("pi_probe_discord.fortigate._route_diagnostic", return_value=(True, "10.10.10.1 via 192.168.1.103")), patch("pi_probe_discord.fortigate._tcp_diagnostic", return_value=(True, "TCP connected")), patch("pi_probe_discord.fortigate.requests.Session", return_value=session):
                snapshot = collect_fortigate_snapshot(config)
            self.assertTrue(snapshot["available"])
            self.assertEqual(snapshot["system"]["hostname"], "fortiwifi")
            self.assertEqual(snapshot["metrics"], {"cpuPercent": 12.5, "memoryPercent": 61.0, "sessions": 42.0})
            self.assertNotIn("secret-token", json.dumps(snapshot))
            self.assertEqual(load_fortigate_state(config)["metrics"]["sessions"], 42.0)
            self.assertEqual(session.get.call_count, 4)
            self.assertEqual(session.get.call_args.kwargs["params"]["access_token"], "secret-token")

    def test_reports_route_failure_without_trying_api(self) -> None:
        config = SimpleNamespace(
            fortigate_enabled=True, fortigate_url="https://10.10.10.1", fortigate_state_json="/tmp/fortigate-test-state.json",
            fortigate_timeout_seconds=3, fortigate_ca_file="", fortigate_tls_verify=True,
        )
        with patch("pi_probe_discord.fortigate._route_diagnostic", return_value=(False, "No route to host")), patch("pi_probe_discord.fortigate.requests.Session") as session:
            snapshot = collect_fortigate_snapshot(config)
        self.assertFalse(snapshot["available"])
        self.assertEqual(snapshot["failureStage"], "route")
        self.assertEqual(snapshot["diagnostics"][0]["stage"], "route")
        session.assert_not_called()
