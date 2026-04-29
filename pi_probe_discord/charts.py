from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import socket
from typing import Any

from .models import SpeedResult
from .status import assess_internet_health

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
except ImportError:
    plt = None
    mdates = None
    mticker = None


@dataclass
class MetricStats:
    latest: float | None
    avg_24h: float | None
    avg_7d: float | None
    min_24h: float | None
    max_24h: float | None
    min_7d: float | None
    max_7d: float | None
    samples_24h: int
    samples_7d: int


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


def _min_max(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    return min(values), max(values)


def calculate_metric_stats(points: list[tuple[datetime, float]], now: datetime) -> MetricStats:
    values_7d = [value for _, value in points]
    values_24h = [value for moment, value in points if moment >= now - timedelta(hours=24)]
    min_24h, max_24h = _min_max(values_24h)
    min_7d, max_7d = _min_max(values_7d)
    return MetricStats(
        latest=values_7d[-1] if values_7d else None,
        avg_24h=_average(values_24h),
        avg_7d=_average(values_7d),
        min_24h=min_24h,
        max_24h=max_24h,
        min_7d=min_7d,
        max_7d=max_7d,
        samples_24h=len(values_24h),
        samples_7d=len(values_7d),
    )


def _comparison_text(metric: str, latest: float | None, avg_24h: float | None) -> tuple[str, str]:
    if latest is None or avg_24h is None or avg_24h <= 0:
        return "Not enough data", "#93a0b3"

    delta = (latest - avg_24h) / avg_24h * 100.0
    abs_delta = abs(delta)
    metric_is_ping = metric == "ping"

    if abs_delta <= 15.0:
        return "Normal", "#34d399"

    if metric_is_ping:
        if delta >= 30.0:
            return f"Degraded — {delta:.0f}% above 24h avg", "#ff6b6b"
        if delta >= 15.0:
            return f"Elevated — {delta:.0f}% above 24h avg", "#fbbf24"
        return f"Improved — {abs_delta:.0f}% below 24h avg", "#34d399"

    if delta <= -30.0:
        return f"Degraded — {abs_delta:.0f}% below 24h avg", "#ff6b6b"
    if delta <= -15.0:
        return f"Below average — {abs_delta:.0f}% below 24h avg", "#fbbf24"
    return f"Above average — {delta:.0f}% above 24h avg", "#34d399"


def _fmt_value(value: float | None, suffix: str, precision: int = 1) -> str:
    if value is None:
        return "not enough data"
    if precision == 0:
        return f"{value:.0f} {suffix}"
    return f"{value:.{precision}f} {suffix}"


def _fmt_range(low: float | None, high: float | None, suffix: str, precision: int = 1) -> str:
    if low is None or high is None:
        return "not enough data"
    if precision == 0:
        return f"{low:.0f}-{high:.0f} {suffix}"
    return f"{low:.{precision}f}-{high:.{precision}f} {suffix}"


def _problem_ranges(
    download_points: list[tuple[datetime, float]],
    ping_points: list[tuple[datetime, float]],
    download_threshold: float,
    ping_threshold: float,
) -> list[tuple[datetime, datetime]]:
    points = []
    for moment, value in download_points:
        if value < download_threshold:
            points.append(moment)
    for moment, value in ping_points:
        if value > ping_threshold:
            points.append(moment)
    points = sorted(set(points))
    if not points:
        return []
    ranges = []
    start = points[0]
    end = points[0]
    for point in points[1:]:
        if (point - end) <= timedelta(hours=6):
            end = point
        else:
            ranges.append((start, end))
            start = end = point
    ranges.append((start, end))
    return ranges


def _render_no_data(ax: Any, title: str) -> None:
    ax.set_facecolor("#11161f")
    ax.set_title(title, loc="left", color="#f4f7fb", fontsize=15, fontweight="bold", pad=16)
    ax.text(0.5, 0.5, "Not enough data", ha="center", va="center", transform=ax.transAxes, color="#93a0b3", fontsize=12)
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_color("#344055")


def _configure_axis(ax: Any, y_label: str) -> None:
    ax.set_facecolor("#11161f")
    ax.grid(color="#232c3b", alpha=1.0, linewidth=0.8)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color("#344055")
    ax.tick_params(colors="#aeb7c5", labelsize=10)
    ax.set_ylabel(y_label, color="#aeb7c5", fontsize=10)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(nbins=6, min_n_ticks=4))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=None))


def _set_time_axis(ax: Any, since: datetime, until: datetime, day_mode: bool, earliest: datetime | None) -> None:
    if day_mode:
        if earliest is None:
            ax.set_xlim(since, until)
            return
        data_start = max(since, earliest - timedelta(hours=4))
        ax.set_xlim(data_start, until)
        ax.xaxis.set_major_locator(mdates.DayLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%a", tz=None))
    else:
        ax.set_xlim(since, until)
        ax.xaxis.set_major_locator(mdates.HourLocator(byhour=[0, 6, 12, 18], tz=since.tzinfo))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=since.tzinfo))


def _plot_speed_chart(
    ax: Any,
    title: str,
    download_points: list[tuple[datetime, float]],
    upload_points: list[tuple[datetime, float]],
    since: datetime,
    until: datetime,
    avg_download: float | None,
    avg_upload: float | None,
    problem_ranges: list[tuple[datetime, datetime]],
    day_mode: bool,
    earliest: datetime | None,
) -> bool:
    if not download_points and not upload_points:
        _render_no_data(ax, title)
        return False

    _configure_axis(ax, "Mbps")
    ax.set_title(title, loc="left", color="#f4f7fb", fontsize=15, fontweight="bold", pad=16)
    if download_points:
        ax.plot([p[0] for p in download_points], [p[1] for p in download_points], color="#39a0ff", marker="o", linewidth=2.4, markersize=3.4, label="Download")
    if upload_points:
        ax.plot([p[0] for p in upload_points], [p[1] for p in upload_points], color="#34d399", marker="o", linewidth=2.4, markersize=3.4, label="Upload")

    if avg_download is not None:
        ax.axhline(avg_download, color="#39a0ff", linestyle="--", linewidth=1.2, alpha=0.7, label="Download avg")
    if avg_upload is not None:
        ax.axhline(avg_upload, color="#34d399", linestyle="--", linewidth=1.2, alpha=0.7, label="Upload avg")

    for index, (start, end) in enumerate(problem_ranges):
        label = "Degraded window" if index == 0 else None
        ax.axvspan(start, end + timedelta(minutes=1), color="#8f2333", alpha=0.18, label=label)

    _set_time_axis(ax, since, until, day_mode, earliest)
    ax.legend(loc="upper right", frameon=False, fontsize=9, ncol=3, labelcolor="#c8d0dd")
    return True


def _plot_ping_chart(
    ax: Any,
    title: str,
    ping_points: list[tuple[datetime, float]],
    since: datetime,
    until: datetime,
    avg_ping: float | None,
    problem_ranges: list[tuple[datetime, datetime]],
    day_mode: bool,
    earliest: datetime | None,
) -> bool:
    if not ping_points:
        _render_no_data(ax, title)
        return False

    _configure_axis(ax, "ms")
    ax.set_title(title, loc="left", color="#f4f7fb", fontsize=15, fontweight="bold", pad=16)
    ax.plot([p[0] for p in ping_points], [p[1] for p in ping_points], color="#ff8a3d", marker="o", linewidth=2.4, markersize=3.4, label="Ping")
    if avg_ping is not None:
        ax.axhline(avg_ping, color="#ff8a3d", linestyle="--", linewidth=1.2, alpha=0.7, label="Ping avg")
    for index, (start, end) in enumerate(problem_ranges):
        label = "Degraded window" if index == 0 else None
        ax.axvspan(start, end + timedelta(minutes=1), color="#8f2333", alpha=0.18, label=label)

    _set_time_axis(ax, since, until, day_mode, earliest)
    ax.legend(loc="upper right", frameon=False, fontsize=9, ncol=3, labelcolor="#c8d0dd")
    return True


def _render_summary_card(
    ax: Any,
    assessment: Any,
    now: datetime,
    down: MetricStats,
    up: MetricStats,
    ping: MetricStats,
) -> None:
    ax.set_facecolor("#151a22")
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_color(assessment.color_hex)
        spine.set_linewidth(2.0)

    latest_summary = f"{_fmt_value(down.latest, 'Mbps')} ↓   {_fmt_value(up.latest, 'Mbps')} ↑   {_fmt_value(ping.latest, 'ms', 0)}"
    avg_summary = f"24h avg: {_fmt_value(down.avg_24h, 'Mbps')} ↓ | {_fmt_value(up.avg_24h, 'Mbps')} ↑ | {_fmt_value(ping.avg_24h, 'ms', 0)}"

    ax.text(0.03, 0.68, assessment.label, transform=ax.transAxes, color=assessment.color_hex, fontsize=20, fontweight="bold", va="center")
    ax.text(0.03, 0.30, avg_summary, transform=ax.transAxes, color="#b6c0d0", fontsize=11, va="center")
    ax.text(0.50, 0.68, latest_summary, transform=ax.transAxes, color="#e7edf7", fontsize=16, fontweight="bold", ha="center", va="center")
    ax.text(0.50, 0.30, assessment.headline, transform=ax.transAxes, color="#b6c0d0", fontsize=10.5, ha="center", va="center")
    ax.text(0.97, 0.68, now.strftime("%H:%M"), transform=ax.transAxes, color="#d9e0ec", fontsize=17, fontweight="bold", ha="right", va="center")
    ax.text(0.97, 0.30, now.strftime("%a %d %b %Z"), transform=ax.transAxes, color="#9ca8bc", fontsize=10.5, ha="right", va="center")


def _render_metric_card(ax: Any, title: str, stats: MetricStats, unit: str, metric_key: str) -> None:
    ax.set_facecolor("#151a22")
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_color("#212938")
        spine.set_linewidth(1.4)

    precision = 0 if unit == "ms" else 1
    latest = _fmt_value(stats.latest, unit, precision)
    comparison, accent = _comparison_text(metric_key, stats.latest, stats.avg_24h)
    avg_24h = _fmt_value(stats.avg_24h, unit, precision)
    avg_7d = _fmt_value(stats.avg_7d, unit, precision)
    range_24h = _fmt_range(stats.min_24h, stats.max_24h, unit, precision)
    range_7d = _fmt_range(stats.min_7d, stats.max_7d, unit, precision)

    ax.text(0.05, 0.83, title, transform=ax.transAxes, color="#95a1b5", fontsize=12.5, va="center")
    ax.text(0.05, 0.63, latest, transform=ax.transAxes, color="#f4f7fb", fontsize=19, fontweight="bold", va="center")
    ax.text(0.05, 0.44, comparison, transform=ax.transAxes, color=accent, fontsize=10.8, fontweight="bold", va="center")
    ax.text(0.05, 0.25, f"24h avg: {avg_24h} | 7d avg: {avg_7d}", transform=ax.transAxes, color="#b3bdd0", fontsize=9.7, va="center")
    ax.text(0.05, 0.10, f"24h range: {range_24h} | 7d range: {range_7d}", transform=ax.transAxes, color="#8f9bb0", fontsize=9.1, va="center")


def generate_chart(history: dict[str, list[dict[str, Any]]], now: datetime, chart_path: str, speed_result: SpeedResult) -> tuple[bool, str]:
    if plt is None or mdates is None:
        return False, "matplotlib not installed"

    fig = plt.figure(figsize=(15.6, 14.2), facecolor="#0f141d")
    gs = fig.add_gridspec(6, 3, height_ratios=[1.2, 1.45, 2.0, 1.8, 2.0, 1.8], hspace=0.62, wspace=0.24)

    history_download = _history_points_for_window(history, "download", now - timedelta(days=7))
    history_upload = _history_points_for_window(history, "upload", now - timedelta(days=7))
    history_ping = _history_points_for_window(history, "ping", now - timedelta(days=7))
    assessment = assess_internet_health(history, now, speed_result)

    down_stats = calculate_metric_stats(history_download, now)
    up_stats = calculate_metric_stats(history_upload, now)
    ping_stats = calculate_metric_stats(history_ping, now)

    status_ax = fig.add_subplot(gs[0, :])
    _render_summary_card(status_ax, assessment, now, down_stats, up_stats, ping_stats)

    _render_metric_card(fig.add_subplot(gs[1, 0]), "Download", down_stats, "Mbps", "download")
    _render_metric_card(fig.add_subplot(gs[1, 1]), "Upload", up_stats, "Mbps", "upload")
    _render_metric_card(fig.add_subplot(gs[1, 2]), "Ping", ping_stats, "ms", "ping")

    since_24h = now - timedelta(hours=24)
    d24 = [point for point in history_download if point[0] >= since_24h]
    u24 = [point for point in history_upload if point[0] >= since_24h]
    p24 = [point for point in history_ping if point[0] >= since_24h]
    ranges_24h = _problem_ranges(d24, p24, assessment.problem_download_threshold, assessment.problem_ping_threshold)
    earliest_24h = min([points[0][0] for points in [d24, u24, p24] if points], default=None)

    ax24_speed = fig.add_subplot(gs[2, :])
    has24_speed = _plot_speed_chart(
        ax24_speed,
        "Last 24 Hours — Download/Upload",
        d24,
        u24,
        since_24h,
        now,
        down_stats.avg_24h,
        up_stats.avg_24h,
        ranges_24h,
        day_mode=False,
        earliest=earliest_24h,
    )
    ax24_ping = fig.add_subplot(gs[3, :])
    has24_ping = _plot_ping_chart(
        ax24_ping,
        "Last 24 Hours — Ping",
        p24,
        since_24h,
        now,
        ping_stats.avg_24h,
        ranges_24h,
        day_mode=False,
        earliest=earliest_24h,
    )

    since_7d = now - timedelta(days=7)
    ranges_7d = _problem_ranges(history_download, history_ping, assessment.problem_download_threshold, assessment.problem_ping_threshold)
    earliest_7d = min([points[0][0] for points in [history_download, history_upload, history_ping] if points], default=None)
    available_note = None
    if earliest_7d is not None and earliest_7d > since_7d + timedelta(hours=3):
        available_note = f"Data available from {earliest_7d.strftime('%d %b %H:%M')}"

    ax7_speed = fig.add_subplot(gs[4, :])
    has7_speed = _plot_speed_chart(
        ax7_speed,
        "Last 7 Days — Download/Upload",
        history_download,
        history_upload,
        since_7d,
        now,
        down_stats.avg_7d,
        up_stats.avg_7d,
        ranges_7d,
        day_mode=True,
        earliest=earliest_7d,
    )
    ax7_ping = fig.add_subplot(gs[5, :])
    has7_ping = _plot_ping_chart(
        ax7_ping,
        "Last 7 Days — Ping",
        history_ping,
        since_7d,
        now,
        ping_stats.avg_7d,
        ranges_7d,
        day_mode=True,
        earliest=earliest_7d,
    )

    fig.text(0.055, 0.975, "Internet Health Snapshot", color="#f4f7fb", fontsize=22, fontweight="bold", ha="left", va="top")
    fig.text(0.055, 0.952, "Dashed lines show period averages. Red shaded windows mark degraded measurements.", color="#9ca8bc", fontsize=10, ha="left", va="top")
    if available_note:
        fig.text(0.945, 0.952, available_note, color="#9ca8bc", fontsize=10, ha="right", va="top")

    footer = (
        f"{socket.gethostname()} · generated {now.strftime('%H:%M %Z')} · "
        f"24h samples: D{down_stats.samples_24h}/U{up_stats.samples_24h}/P{ping_stats.samples_24h} · "
        f"7d samples: D{down_stats.samples_7d}/U{up_stats.samples_7d}/P{ping_stats.samples_7d}"
    )
    fig.text(0.055, 0.017, footer, color="#8f9bb0", fontsize=9.8, ha="left", va="bottom")

    if not any([has24_speed, has24_ping, has7_speed, has7_ping]):
        plt.close(fig)
        return False, "No speed data available yet"

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, facecolor=fig.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(fig)
    return True, "Chart generated"
