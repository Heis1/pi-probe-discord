from __future__ import annotations

from .models import SpeedResult

try:
    import speedtest  # type: ignore
except ImportError:
    speedtest = None


def run_speedtest_measurement() -> SpeedResult:
    if speedtest is None:
        return SpeedResult(ok=False, summary="Speedtest module not installed.", warnings=["python speedtest module unavailable"])

    try:
        tester = speedtest.Speedtest()
        tester.get_best_server()
        download = tester.download() / 1_000_000
        upload = tester.upload() / 1_000_000
        ping = tester.results.ping
        summary = f"Download {download:.2f} Mbps | Upload {upload:.2f} Mbps | Ping {ping:.2f} ms"
        return SpeedResult(ok=True, summary=summary, download_mbps=download, upload_mbps=upload, ping_ms=ping)
    except speedtest.SpeedtestException as exc:  # type: ignore[attr-defined]
        return SpeedResult(ok=False, summary="Speedtest failed.", warnings=[str(exc)])
    except Exception as exc:
        return SpeedResult(ok=False, summary="Unexpected speedtest error.", warnings=[str(exc)])

