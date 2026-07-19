from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .baselines import average, calculate_same_time_baseline, history_points_for_window
from .models import SpeedResult


@dataclass
class StatusAssessment:
    label: str
    color_hex: str
    discord_color: int
    headline: str
    detail: str
    download_state: str
    upload_state: str
    ping_state: str
    problem_download_threshold: float
    problem_ping_threshold: float
    download_baseline: float | None = None
    upload_baseline: float | None = None
    ping_baseline: float | None = None

def _recent_average(points: list[tuple[datetime, float]], now: datetime, window: timedelta) -> float | None:
    values = [value for moment, value in points if moment >= now - window]
    return average(values)


def assess_internet_health(history: dict[str, list[dict[str, Any]]], now: datetime, speed_result: SpeedResult) -> StatusAssessment:
    history_download = history_points_for_window(history, "download", now - timedelta(days=7))
    history_upload = history_points_for_window(history, "upload", now - timedelta(days=7))
    history_ping = history_points_for_window(history, "ping", now - timedelta(days=7))

    current_download = speed_result.download_mbps
    current_upload = speed_result.upload_mbps
    current_ping = speed_result.ping_ms

    if current_download is None or current_ping is None:
        return StatusAssessment(
            label="WAITING FOR DATA",
            color_hex="#fbbf24",
            discord_color=16766720,
            headline="Waiting for enough local history to judge the connection.",
            detail="Need more speed tests before a household-specific verdict is possible.",
            download_state="n/a",
            upload_state="n/a",
            ping_state="n/a",
            problem_download_threshold=0.0,
            problem_ping_threshold=9999.0,
        )

    avg_download_7d = average([value for _, value in history_download]) or current_download
    avg_upload_7d = average([value for _, value in history_upload]) or (current_upload if current_upload is not None else 0.0)
    avg_ping_7d = average([value for _, value in history_ping]) or current_ping

    avg_download_24h = _recent_average(history_download, now, timedelta(hours=24)) or avg_download_7d
    avg_upload_24h = _recent_average(history_upload, now, timedelta(hours=24)) or avg_upload_7d
    avg_ping_24h = _recent_average(history_ping, now, timedelta(hours=24)) or avg_ping_7d

    same_time_download = calculate_same_time_baseline(history_download, now).avg
    same_time_upload = calculate_same_time_baseline(history_upload, now).avg
    same_time_ping = calculate_same_time_baseline(history_ping, now).avg

    download_baseline = same_time_download or min(avg_download_7d, avg_download_24h)
    upload_baseline = same_time_upload or min(avg_upload_7d, avg_upload_24h)
    ping_baseline = same_time_ping or max(avg_ping_7d, avg_ping_24h)

    unstable_download_threshold = max(15.0, download_baseline * 0.75)
    degraded_download_threshold = max(10.0, download_baseline * 0.5)
    unstable_ping_threshold = max(80.0, ping_baseline * 1.6)
    degraded_ping_threshold = max(150.0, ping_baseline * 2.5)
    unstable_upload_threshold = max(3.0, upload_baseline * 0.6) if upload_baseline else 0.0

    download_state = "Good"
    if current_download <= degraded_download_threshold:
        download_state = "Very slow"
    elif current_download <= unstable_download_threshold:
        download_state = "Slower than normal"

    upload_state = "Good"
    if current_upload is not None and current_upload <= unstable_upload_threshold:
        upload_state = "Low"

    ping_state = "Good"
    if current_ping >= degraded_ping_threshold:
        ping_state = "Very high"
    elif current_ping >= unstable_ping_threshold:
        ping_state = "Higher than normal"

    if current_download <= degraded_download_threshold or current_ping >= degraded_ping_threshold:
        return StatusAssessment(
            label="INTERNET DEGRADED",
            color_hex="#ff6b6b",
            discord_color=15158332,
            headline="Connection problem detected against your recent same-time baseline.",
            detail="Download or ping moved well outside what this connection usually does around this time of day.",
            download_state=download_state,
            upload_state=upload_state,
            ping_state=ping_state,
            problem_download_threshold=unstable_download_threshold,
            problem_ping_threshold=unstable_ping_threshold,
            download_baseline=download_baseline,
            upload_baseline=upload_baseline,
            ping_baseline=ping_baseline,
        )

    if (
        current_download <= unstable_download_threshold
        or current_ping >= unstable_ping_threshold
        or (current_upload is not None and current_upload <= unstable_upload_threshold)
    ):
        return StatusAssessment(
            label="INTERNET SLOWER THAN NORMAL",
            color_hex="#fbbf24",
            discord_color=16766720,
            headline="Internet is usable, but performance is below its usual level for this time of day.",
            detail="This verdict prefers matching prior runs from the same time slot, then falls back to recent 24-hour and 7-day history.",
            download_state=download_state,
            upload_state=upload_state,
            ping_state=ping_state,
            problem_download_threshold=unstable_download_threshold,
            problem_ping_threshold=unstable_ping_threshold,
            download_baseline=download_baseline,
            upload_baseline=upload_baseline,
            ping_baseline=ping_baseline,
        )

    return StatusAssessment(
        label="INTERNET HEALTHY",
        color_hex="#34d399",
        discord_color=3066993,
        headline="No obvious internet problem detected for this time of day.",
        detail="Current speed and latency are inside the expected range for this connection's usual time-slot behavior.",
        download_state=download_state,
        upload_state=upload_state,
        ping_state=ping_state,
        problem_download_threshold=unstable_download_threshold,
        problem_ping_threshold=unstable_ping_threshold,
        download_baseline=download_baseline,
        upload_baseline=upload_baseline,
        ping_baseline=ping_baseline,
    )
