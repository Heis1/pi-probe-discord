from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


@dataclass
class TimeSlotBaseline:
    avg: float | None
    low: float | None
    high: float | None
    sample_count: int


def history_points_for_window(history: dict[str, list[dict[str, Any]]], metric: str, cutoff: datetime) -> list[tuple[datetime, float]]:
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


def average(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def min_max(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    return min(values), max(values)


def _minutes_since_midnight(moment: datetime) -> int:
    return moment.hour * 60 + moment.minute


def _time_of_day_distance_minutes(left: datetime, right: datetime) -> int:
    left_minutes = _minutes_since_midnight(left)
    right_minutes = _minutes_since_midnight(right)
    direct = abs(left_minutes - right_minutes)
    return min(direct, 1440 - direct)


def calculate_same_time_baseline(
    points: list[tuple[datetime, float]],
    reference: datetime,
    lookback_days: int = 7,
    tolerance_minutes: int = 90,
    min_samples: int = 2,
) -> TimeSlotBaseline:
    cutoff = reference - timedelta(days=lookback_days)
    closest_by_day: dict[datetime.date, tuple[int, float]] = {}

    for moment, value in points:
        if moment < cutoff or moment >= reference or moment.date() == reference.date():
            continue
        distance = _time_of_day_distance_minutes(moment, reference)
        if distance > tolerance_minutes:
            continue
        current = closest_by_day.get(moment.date())
        if current is None or distance < current[0]:
            closest_by_day[moment.date()] = (distance, value)

    values = [value for _, value in closest_by_day.values()]
    if len(values) < min_samples:
        return TimeSlotBaseline(avg=None, low=None, high=None, sample_count=len(values))

    low, high = min_max(values)
    return TimeSlotBaseline(avg=average(values), low=low, high=high, sample_count=len(values))


def build_same_time_baseline_series(
    history_points: list[tuple[datetime, float]],
    target_points: list[tuple[datetime, float]],
    lookback_days: int = 7,
    tolerance_minutes: int = 90,
    min_samples: int = 2,
) -> list[tuple[datetime, float]]:
    baseline_points: list[tuple[datetime, float]] = []
    for moment, _ in target_points:
        baseline = calculate_same_time_baseline(
            history_points,
            reference=moment,
            lookback_days=lookback_days,
            tolerance_minutes=tolerance_minutes,
            min_samples=min_samples,
        )
        if baseline.avg is not None:
            baseline_points.append((moment, baseline.avg))
    return baseline_points
