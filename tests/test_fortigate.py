from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pi_probe_discord.fortigate import classify_fortigate_event, collect_fortigate_snapshot, load_fortigate_state, summarise_fortigate_syslog


class FortigateTests(unittest.TestCase):
    def test_classifies_doh_as_enforced_dns_policy_not_compromise(self) -> None:
        line = 'type="utm" subtype="app-ctrl" app="DNS.Over.HTTPS" action="block" srcip=192.168.20.102 policyid=20'
        self.assertEqual(classify_fortigate_event(line), "dns_bypass_block")

    def test_syslog_summary_is_bounded_and_preserves_event_categories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fortigate.log"
            path.write_text(
                '\n'.join([
                    f'{datetime.now().astimezone().isoformat()} source=192.168.10.1 type="utm" subtype="ips" action="blocked" srcip=192.168.20.102',
                    f'{datetime.now().astimezone().isoformat()} source=192.168.10.1 type="traffic" action="deny" srcip=192.168.20.102 dstip=192.168.10.10 policyid=0',
                    f'{datetime.now().astimezone().isoformat()} source=192.168.10.1 type="event" subtype="system" msg="Admin login failed" status="fail" srcip=192.168.10.20',
                ]),
                encoding="utf-8",
            )
            summary = summarise_fortigate_syslog(str(path))
        self.assertTrue(summary["available"])
        self.assertEqual(summary["counts"]["ips_prevention"], 1)
        self.assertEqual(summary["counts"]["firewall_deny"], 1)
        self.assertEqual(summary["counts"]["management_login_failure"], 1)

    def test_collects_monitor_metrics_and_persists_safe_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            secret_file = base / "fortigate.env"
            state_file = base / "fortigate" / "latest.json"
            secret_file.write_text('PI_PROBE_FORTIGATE_API_TOKEN="secret-token"\n', encoding="utf-8")
            config = SimpleNamespace(
                fortigate_enabled=True,
                fortigate_url="https://198.51.100.1",
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
            with patch("pathlib.Path.stat", return_value=fake_stat), patch("pi_probe_discord.fortigate._route_diagnostic", return_value=(True, "198.51.100.1 via 192.0.2.10")), patch("pi_probe_discord.fortigate._tcp_diagnostic", return_value=(True, "TCP connected")), patch("pi_probe_discord.fortigate.requests.Session", return_value=session):
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
            fortigate_enabled=True, fortigate_url="https://198.51.100.1", fortigate_state_json="/tmp/fortigate-test-state.json",
            fortigate_timeout_seconds=3, fortigate_ca_file="", fortigate_tls_verify=True,
        )
        with patch("pi_probe_discord.fortigate._route_diagnostic", return_value=(False, "No route to host")), patch("pi_probe_discord.fortigate.requests.Session") as session:
            snapshot = collect_fortigate_snapshot(config)
        self.assertFalse(snapshot["available"])
        self.assertEqual(snapshot["failureStage"], "route")
        self.assertEqual(snapshot["diagnostics"][0]["stage"], "route")
        session.assert_not_called()
