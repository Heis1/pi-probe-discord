from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from .models import SpeedResult

try:
    import speedtest  # type: ignore
except ImportError:
    speedtest = None


def _load_ookla_result(stdout: str) -> dict[str, object]:
    """Ookla can print a one-time license notice before its JSON result."""
    for line in reversed(stdout.splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "download" in payload and "upload" in payload and "ping" in payload:
            return payload
    raise ValueError("Ookla Speedtest did not return a JSON result.")


def _official_speedtest_cli() -> SpeedResult | None:
    """Use Ookla's native client when installed; speedtest-cli is unreliable on fast links."""
    binary = Path(os.environ.get("PI_PROBE_OOKLA_SPEEDTEST_BIN", "/usr/local/bin/ookla-speedtest"))
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return None
    try:
        command = [str(binary), "--accept-license", "--accept-gdpr", "--format=json"]
        server_id = os.environ.get("PI_PROBE_SPEEDTEST_SERVER_ID", "").strip()
        if server_id:
            command.extend(["--server-id", server_id])
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        payload = _load_ookla_result(completed.stdout)
        download = float(payload["download"]["bandwidth"]) * 8 / 1_000_000
        upload = float(payload["upload"]["bandwidth"]) * 8 / 1_000_000
        ping = float(payload["ping"]["latency"])
        server = payload.get("server", {})
        server_name = " ".join(str(server.get(key, "")).strip() for key in ("name", "location") if server.get(key)).strip()
        warnings = [f"Ookla server: {server_name}"] if server_name else []
        return SpeedResult(
            ok=True,
            summary=f"Download {download:.2f} Mbps | Upload {upload:.2f} Mbps | Ping {ping:.2f} ms",
            download_mbps=download,
            upload_mbps=upload,
            ping_ms=ping,
            warnings=warnings,
        )
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return SpeedResult(ok=False, summary="Ookla Speedtest failed.", warnings=[str(exc)])


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
    official_result = _official_speedtest_cli()
    if official_result is not None:
        return official_result

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
