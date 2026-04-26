from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
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


def _distinct_local_days(*series: list[tuple[datetime, float]]) -> set[datetime.date]:
    days = set()
    for points in series:
        for moment, _ in points:
            days.add(moment.date())
    return days


def _configure_y_axis(ax: Any, *series: list[tuple[datetime, float]]) -> None:
    values: list[float] = []
    for points in series:
        values.extend(value for _, value in points)
    if not values:
        return

    minimum = min(values)
    maximum = max(values)
    span = max(maximum - minimum, 8.0)
    lower = max(0.0, minimum - span * 0.18)
    upper = maximum + span * 0.18
    ax.set_ylim(lower, upper)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(nbins=6, min_n_ticks=4))


def _sample_mode_labels(*series: list[tuple[datetime, float]]) -> list[str]:
    seen: list[str] = []
    for points in series:
        for moment, _ in points:
            label = moment.strftime("%H:%M")
            if label not in seen:
                seen.append(label)
    return seen


def _render_sparse_state(ax: Any, count: int) -> None:
    ax.text(
        0.985,
        1.13,
        f"{count} checks so far today",
        transform=ax.transAxes,
        color="#93a0b3",
        fontsize=10,
        ha="right",
        va="center",
    )


def _render_series_key(ax: Any) -> None:
    items = [("Download", "#39a0ff"), ("Upload", "#34d399"), ("Ping", "#ff8a3d")]
    x = 0.0
    for label, color in items:
        ax.text(
            x,
            1.11,
            f"● {label}",
            transform=ax.transAxes,
            color=color,
            fontsize=11.5,
            fontweight="bold",
            ha="left",
            va="center",
        )
        x += 0.15


def _render_weekly_building_state(ax: Any, covered_days: int) -> None:
    ax.text(
        0.5,
        0.64,
        "Weekly view is still filling in",
        ha="center",
        va="center",
        transform=ax.transAxes,
        color="#f4f7fb",
        fontsize=20,
        fontweight="bold",
    )
    ax.text(
        0.5,
        0.47,
        f"Only {covered_days} of the last 7 local days has usable history so far.",
        ha="center",
        va="center",
        transform=ax.transAxes,
        color="#c8d0dd",
        fontsize=13.5,
    )
    ax.text(
        0.5,
        0.30,
        "Leave the timer running and this panel will turn into a proper weekly trend automatically.",
        ha="center",
        va="center",
        transform=ax.transAxes,
        color="#93a0b3",
        fontsize=11,
    )


def _plot_window(
    ax: Any,
    history: dict[str, list[dict[str, Any]]],
    since: datetime,
    until: datetime,
    title: str,
    formatter: str,
    problem_download_threshold: float,
    problem_ping_threshold: float,
    daily_ticks: bool = False,
    min_days_required: int = 1,
) -> bool:
    download_points = _history_points_for_window(history, "download", since)
    upload_points = _history_points_for_window(history, "upload", since)
    ping_points = _history_points_for_window(history, "ping", since)
    has_data = bool(download_points or upload_points or ping_points)

    ax.set_facecolor("#11161f")
    ax.set_title(title, loc="left", color="#f4f7fb", fontsize=18, fontweight="bold", pad=18)

    if not has_data:
        ax.text(0.5, 0.5, "No data in this period", ha="center", va="center", transform=ax.transAxes, color="#93a0b3")
        ax.set_xticks([])
        ax.set_yticks([])
        return False

    covered_days = _distinct_local_days(download_points, upload_points, ping_points)
    if daily_ticks and len(covered_days) < min_days_required:
        _render_weekly_building_state(ax, len(covered_days))
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_color("#344055")
        return False

    ax.grid(color="#232c3b", alpha=1.0, linewidth=0.8)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color("#344055")
    ax.tick_params(colors="#aeb7c5", labelsize=12)
    ax.set_ylabel("Mbps / ms", color="#aeb7c5", fontsize=12)
    ax.margins(x=0.02, y=0.16)
    _render_series_key(ax)

    sparse_recent = not daily_ticks and len(_distinct_local_days(download_points, upload_points, ping_points)) <= 1 and max(
        len(download_points), len(upload_points), len(ping_points)
    ) < 8

    if sparse_recent:
        title = "Recent Checks"
        ax.set_title(title, loc="left", color="#f4f7fb", fontsize=20, fontweight="bold", pad=20)
        labels = _sample_mode_labels(download_points, upload_points, ping_points)
        count = len(labels)
        xs = list(range(count))

        down_map = {moment.strftime("%H:%M"): value for moment, value in download_points}
        up_map = {moment.strftime("%H:%M"): value for moment, value in upload_points}
        ping_map = {moment.strftime("%H:%M"): value for moment, value in ping_points}

        down_values = [down_map[label] for label in labels if label in down_map]
        up_values = [up_map[label] for label in labels if label in up_map]
        ping_values = [ping_map[label] for label in labels if label in ping_map]

        ordered_down = [down_map.get(label, down_values[-1] if down_values else 0.0) for label in labels]
        ordered_up = [up_map.get(label, up_values[-1] if up_values else 0.0) for label in labels]
        ordered_ping = [ping_map.get(label, ping_values[-1] if ping_values else 0.0) for label in labels]

        if ordered_down:
            ax.plot(xs, ordered_down, color="#39a0ff", marker="o", linewidth=3.0, markersize=5, label="Download")
        if ordered_up:
            ax.plot(xs, ordered_up, color="#34d399", marker="o", linewidth=3.0, markersize=5, label="Upload")
        if ordered_ping:
            ax.plot(xs, ordered_ping, color="#ff8a3d", marker="o", linewidth=3.0, markersize=5, label="Ping")

        ax.set_xlim(-0.1, max(count - 0.9, 0.9))
        ax.set_xticks(xs)
        ax.set_xticklabels(labels, color="#aeb7c5", fontsize=12)
        _configure_y_axis(
            ax,
            [(datetime.now(), value) for value in ordered_down],
            [(datetime.now(), value) for value in ordered_up],
            [(datetime.now(), value) for value in ordered_ping],
        )
        _render_sparse_state(ax, count)
    else:
        for start, end in _problem_ranges(download_points, ping_points, problem_download_threshold, problem_ping_threshold):
            ax.axvspan(start, end + timedelta(minutes=1), color="#8f2333", alpha=0.22)

        if download_points:
            ax.plot([p[0] for p in download_points], [p[1] for p in download_points], color="#39a0ff", marker="o", linewidth=3.0, markersize=4, label="Download")
        if upload_points:
            ax.plot([p[0] for p in upload_points], [p[1] for p in upload_points], color="#34d399", marker="o", linewidth=3.0, markersize=4, label="Upload")
        if ping_points:
            ax.plot([p[0] for p in ping_points], [p[1] for p in ping_points], color="#ff8a3d", marker="o", linewidth=3.0, markersize=4, label="Ping")

        _configure_y_axis(ax, download_points, upload_points, ping_points)
        ax.xaxis.set_major_formatter(mdates.DateFormatter(formatter, tz=since.tzinfo))
        if daily_ticks:
            ax.xaxis.set_major_locator(mdates.DayLocator())
            start_day = since.replace(hour=0, minute=0, second=0, microsecond=0)
            end_day = (until + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            ax.set_xlim(start_day, end_day)
        else:
            ax.xaxis.set_major_locator(mdates.HourLocator(byhour=[0, 6, 12, 18], tz=since.tzinfo))
            ax.set_xlim(since, until)

    if daily_ticks:
        ax.xaxis.set_major_locator(mdates.DayLocator())
        start_day = since.replace(hour=0, minute=0, second=0, microsecond=0)
        end_day = (until + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        ax.set_xlim(start_day, end_day)
    return True


def generate_chart(history: dict[str, list[dict[str, Any]]], now: datetime, chart_path: str, speed_result: SpeedResult) -> tuple[bool, str]:
    if plt is None or mdates is None:
        return False, "matplotlib not installed"

    fig = plt.figure(figsize=(15.2, 12.2), facecolor="#0f141d")
    gs = fig.add_gridspec(4, 3, height_ratios=[1.45, 1.25, 2.55, 2.35], hspace=0.62, wspace=0.24)

    history_download = _history_points_for_window(history, "download", now - timedelta(days=365))
    history_upload = _history_points_for_window(history, "upload", now - timedelta(days=365))
    history_ping = _history_points_for_window(history, "ping", now - timedelta(days=365))
    current_download = history_download[-1][1] if history_download else None
    current_upload = history_upload[-1][1] if history_upload else None
    current_ping = history_ping[-1][1] if history_ping else None
    assessment = assess_internet_health(history, now, speed_result)

    status_ax = fig.add_subplot(gs[0, :])
    status_ax.set_facecolor("#151a22")
    status_ax.set_xticks([])
    status_ax.set_yticks([])
    for spine in status_ax.spines.values():
        spine.set_color(assessment.color_hex)
        spine.set_linewidth(2.2)
    status_ax.text(0.03, 0.68, assessment.label, transform=status_ax.transAxes, color=assessment.color_hex, fontsize=26, fontweight="bold", va="center")
    status_ax.text(0.03, 0.36, assessment.headline, transform=status_ax.transAxes, color="#e5ebf4", fontsize=14.5, va="center")
    status_ax.text(0.97, 0.66, now.strftime("%H:%M"), transform=status_ax.transAxes, color="#c4ccd8", fontsize=20, ha="right", fontweight="bold", va="center")
    status_ax.text(0.97, 0.36, now.strftime("%a %d %b %Z"), transform=status_ax.transAxes, color="#8d98ab", fontsize=12, ha="right", va="center")

    card_titles = ["Download", "Upload", "Ping"]
    card_values = [
        (
            f"{current_download:.1f} Mbps" if current_download is not None else "n/a",
            "#ff6b6b" if assessment.download_state == "Very slow" else "#fbbf24" if assessment.download_state == "Slower than normal" else "#34d399",
            assessment.download_state,
        ),
        (
            f"{current_upload:.1f} Mbps" if current_upload is not None else "n/a",
            "#fbbf24" if assessment.upload_state == "Low" else "#34d399",
            assessment.upload_state,
        ),
        (
            f"{current_ping:.0f} ms" if current_ping is not None else "n/a",
            "#ff6b6b" if assessment.ping_state == "Very high" else "#fbbf24" if assessment.ping_state == "Higher than normal" else "#34d399",
            assessment.ping_state,
        ),
    ]

    for index in range(3):
        ax = fig.add_subplot(gs[1, index])
        ax.set_facecolor("#151a22")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_color("#212938")
            spine.set_linewidth(1.4)
        value, accent, subtitle = card_values[index]
        ax.text(0.06, 0.75, card_titles[index], transform=ax.transAxes, color="#95a1b5", fontsize=13.5, va="center")
        ax.text(0.06, 0.50, value, transform=ax.transAxes, color="#f4f7fb", fontsize=25, fontweight="bold", va="center")
        ax.text(0.06, 0.22, subtitle, transform=ax.transAxes, color=accent, fontsize=13.5, fontweight="bold", va="center")
        ax.plot([0.93, 0.93], [0.18, 0.82], transform=ax.transAxes, color=accent, linewidth=5.5, solid_capstyle="round")

    ax24 = fig.add_subplot(gs[2, :])
    ax7 = fig.add_subplot(gs[3, :])
    has_day = _plot_window(
        ax24,
        history,
        now - timedelta(hours=24),
        now,
        "Last 24 Hours",
        "%H:%M",
        assessment.problem_download_threshold,
        assessment.problem_ping_threshold,
        daily_ticks=False,
    )
    has_week = _plot_window(
        ax7,
        history,
        now - timedelta(days=7),
        now,
        "Last 7 Days",
        "%a",
        assessment.problem_download_threshold,
        assessment.problem_ping_threshold,
        daily_ticks=True,
        min_days_required=2,
    )

    fig.text(0.055, 0.975, "Internet Health Snapshot", color="#f4f7fb", fontsize=24, fontweight="bold", ha="left", va="top")

    if not has_day and not has_week:
        plt.close(fig)
        return False, "No speed data available yet"

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, facecolor=fig.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(fig)
    return True, "Chart generated"
