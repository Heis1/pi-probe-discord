from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pi_probe_discord.models import SpeedResult
from pi_probe_discord.speedtest_runner import _official_speedtest_cli, run_speedtest_measurement


class SpeedtestRunnerTests(unittest.TestCase):
    def test_official_client_accepts_license_banner_before_json(self) -> None:
        binary = Path(tempfile.mkdtemp()) / "ookla-speedtest"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        output = "License acceptance recorded. Continuing.\n" + (
            '{"download":{"bandwidth":50000000},"upload":{"bandwidth":5000000},'
            '"ping":{"latency":2.5},"server":{"name":"Example","location":"Adelaide"}}\n'
        )
        with patch.dict(os.environ, {"PI_PROBE_OOKLA_SPEEDTEST_BIN": str(binary)}, clear=False), patch(
            "pi_probe_discord.speedtest_runner.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr=""),
        ):
            result = _official_speedtest_cli()

        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result.ok)
        self.assertEqual(result.download_mbps, 400.0)
        self.assertEqual(result.upload_mbps, 40.0)
        self.assertEqual(result.ping_ms, 2.5)

    def test_falls_back_when_native_ookla_client_fails(self) -> None:
        failed = SpeedResult(ok=False, summary="Ookla Speedtest failed.", warnings=["native abort"])
        fallback = SpeedResult(ok=True, summary="fallback ok", download_mbps=100, upload_mbps=20, ping_ms=5)
        with patch("pi_probe_discord.speedtest_runner._official_speedtest_cli", return_value=failed), patch(
            "pi_probe_discord.speedtest_runner._fallback_speedtest_cli", return_value=fallback
        ):
            result = run_speedtest_measurement()
        self.assertTrue(result.ok)
        self.assertEqual(result.summary, "fallback ok")
        self.assertIn("native abort", result.warnings[0])


if __name__ == "__main__":
    unittest.main()
