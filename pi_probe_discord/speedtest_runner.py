from __future__ import annotations

import json
import subprocess

from .models import SpeedResult

try:
    import speedtest  # type: ignore
except ImportError:
    speedtest = None


def _fallback_speedtest_cli() -> SpeedResult:
    try:
        completed = subprocess.run(
            ["speedtest-cli", "--json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        payload = json.loads(completed.stdout)
        download = float(payload["download"]) / 1_000_000
        upload = float(payload["upload"]) / 1_000_000
        ping = float(payload["ping"])
        summary = f"Download {download:.2f} Mbps | Upload {upload:.2f} Mbps | Ping {ping:.2f} ms"
        return SpeedResult(
            ok=True,
            summary=summary,
            download_mbps=download,
            upload_mbps=upload,
            ping_ms=ping,
            warnings=["Used speedtest-cli fallback"],
        )
    except Exception as exc:
        return SpeedResult(ok=False, summary="Speedtest failed.", warnings=[str(exc)])


def run_speedtest_measurement() -> SpeedResult:
    if speedtest is None:
        fallback = _fallback_speedtest_cli()
        if fallback.ok:
            return fallback
        return SpeedResult(ok=False, summary="Speedtest module not installed.", warnings=["python speedtest module unavailable", *fallback.warnings])

    try:
        tester = speedtest.Speedtest()
        tester.get_best_server()
        download = tester.download() / 1_000_000
        upload = tester.upload() / 1_000_000
        ping = tester.results.ping
        summary = f"Download {download:.2f} Mbps | Upload {upload:.2f} Mbps | Ping {ping:.2f} ms"
        return SpeedResult(ok=True, summary=summary, download_mbps=download, upload_mbps=upload, ping_ms=ping)
    except speedtest.SpeedtestException as exc:  # type: ignore[attr-defined]
        fallback = _fallback_speedtest_cli()
        if fallback.ok:
            fallback.warnings.insert(0, f"python speedtest failed: {exc}")
            return fallback
        return SpeedResult(ok=False, summary="Speedtest failed.", warnings=[str(exc), *fallback.warnings])
    except Exception as exc:
        fallback = _fallback_speedtest_cli()
        if fallback.ok:
            fallback.warnings.insert(0, f"python speedtest failed: {exc}")
            return fallback
        return SpeedResult(ok=False, summary="Unexpected speedtest error.", warnings=[str(exc), *fallback.warnings])
