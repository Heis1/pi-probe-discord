from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

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


def _history_points_for_window(history: dict[str, list[dict[str, Any]]], metric: str, cutoff: datetime) -> list[tuple[datetime, float]]:
    points: list[tuple[datetime, float]] = []
    for point in history.get(metric, []):
        timestamp_raw = point.get("x")
        value_raw = point.get("y")
        if not isinstance(timestamp_raw, str) or not isinstance(value_raw, (int, float)):
            continue
        try:
            point_time = datetime.fromisoformat(timestamp_raw)
        except ValueError:
            continue
        if point_time >= cutoff:
            points.append((point_time, float(value_raw)))
    points.sort(key=lambda item: item[0])
    return points


def _average(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _recent_average(points: list[tuple[datetime, float]], now: datetime, window: timedelta) -> float | None:
    values = [value for moment, value in points if moment >= now - window]
    return _average(values)


def assess_internet_health(history: dict[str, list[dict[str, Any]]], now: datetime, speed_result: SpeedResult) -> StatusAssessment:
    history_download = _history_points_for_window(history, "download", now - timedelta(days=7))
    history_upload = _history_points_for_window(history, "upload", now - timedelta(days=7))
    history_ping = _history_points_for_window(history, "ping", now - timedelta(days=7))

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

    avg_download_7d = _average([value for _, value in history_download]) or current_download
    avg_upload_7d = _average([value for _, value in history_upload]) or (current_upload if current_upload is not None else 0.0)
    avg_ping_7d = _average([value for _, value in history_ping]) or current_ping

    avg_download_24h = _recent_average(history_download, now, timedelta(hours=24)) or avg_download_7d
    avg_ping_24h = _recent_average(history_ping, now, timedelta(hours=24)) or avg_ping_7d

    unstable_download_threshold = max(15.0, min(avg_download_7d, avg_download_24h) * 0.75)
    degraded_download_threshold = max(10.0, min(avg_download_7d, avg_download_24h) * 0.5)
    unstable_ping_threshold = max(80.0, max(avg_ping_7d, avg_ping_24h) * 1.6)
    degraded_ping_threshold = max(150.0, max(avg_ping_7d, avg_ping_24h) * 2.5)
    unstable_upload_threshold = max(3.0, avg_upload_7d * 0.6) if avg_upload_7d else 0.0

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
            headline="Connection problem detected against your recent normal baseline.",
            detail=f"Download or ping moved well outside the last 7 days of normal behavior.",
            download_state=download_state,
            upload_state=upload_state,
            ping_state=ping_state,
            problem_download_threshold=unstable_download_threshold,
            problem_ping_threshold=unstable_ping_threshold,
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
            headline="Internet is usable, but performance is below your recent normal range.",
            detail="This verdict is based on your recent 24-hour and 7-day history, not a generic fixed speed threshold.",
            download_state=download_state,
            upload_state=upload_state,
            ping_state=ping_state,
            problem_download_threshold=unstable_download_threshold,
            problem_ping_threshold=unstable_ping_threshold,
        )

    return StatusAssessment(
        label="INTERNET HEALTHY",
        color_hex="#34d399",
        discord_color=3066993,
        headline="No obvious internet problem detected from your recent local history.",
        detail="Current speed and latency are inside the expected range for this connection.",
        download_state=download_state,
        upload_state=upload_state,
        ping_state=ping_state,
        problem_download_threshold=unstable_download_threshold,
        problem_ping_threshold=unstable_ping_threshold,
    )

