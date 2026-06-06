from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata as importlib_metadata
import json
from pathlib import Path
from typing import Any

from .baselines import average, history_points_for_window
from .models import AppConfig, SpeedResult

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


DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
STATUS_FILE_NAME = "status.json"
SERVICE_NAME = "pi-probe-discord-dashboard"


@dataclass
class DashboardThresholds:
    outage_download_mbps: float
    degraded_download_mbps: float
    high_ping_ms: float
    failed_test_is_outage: bool
    heatmap_good_mbps: float
    heatmap_warn_mbps: float


@dataclass
class DashboardRow:
    timestamp: datetime
    download: float | None
    upload: float | None
    ping: float | None
    speed_ok: bool = True
    speed_summary: str = ""
    speed_warnings: str = ""
    status: str = "normal"
    is_failed: bool = False
    is_outage: bool = False
    is_degraded: bool = False


@dataclass
class RouterEvent:
    timestamp: datetime
    event_type: str
    message: str
    severity: str = "info"
    source: str = ""


@dataclass
class PiholeHourlyRow:
    timestamp: datetime
    dns_queries: float | None
    blocked_queries: float | None
    blocked_percent: float | None


def _format_metric(value: float | None, suffix: str, precision: int = 1) -> str:
    if value is None:
        return "n/a"
    if precision == 0:
        return f"{value:.0f} {suffix}"
    return f"{value:.{precision}f} {suffix}"


def _quantile(values: list[float], q: float) -> float | None:
    clean = sorted(values)
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    pos = (len(clean) - 1) * q
    base = int(pos)
    rest = pos - base
    if base + 1 >= len(clean):
        return clean[base]
    return clean[base] + rest * (clean[base + 1] - clean[base])


def _score_connection(avg_down: float | None, avg_up: float | None, avg_ping: float | None, pct_250: float) -> int:
    if avg_down is None or avg_up is None or avg_ping is None:
        return 0
    score = 0.0
    score += min(avg_down / 3.5, 40.0)
    score += min(avg_up / 0.8, 20.0)
    score += max(0.0, 20.0 - max(avg_ping - 3.0, 0.0) * 2.2)
    score += pct_250 * 0.2
    return max(0, min(100, round(score)))


def _safe_float(value: Any) -> float | None:
    if value in (None, "", "null"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def _build_thresholds(config: AppConfig | None) -> DashboardThresholds:
    if config is None:
        return DashboardThresholds(
            outage_download_mbps=50.0,
            degraded_download_mbps=250.0,
            high_ping_ms=20.0,
            failed_test_is_outage=True,
            heatmap_good_mbps=320.0,
            heatmap_warn_mbps=250.0,
        )
    return DashboardThresholds(
        outage_download_mbps=config.outage_download_mbps,
        degraded_download_mbps=config.degraded_download_mbps,
        high_ping_ms=config.high_ping_ms,
        failed_test_is_outage=config.failed_test_is_outage,
        heatmap_good_mbps=config.heatmap_good_mbps,
        heatmap_warn_mbps=config.heatmap_warn_mbps,
    )


def _classify_row(row: DashboardRow, thresholds: DashboardThresholds) -> DashboardRow:
    failed = (not row.speed_ok) or row.download is None or row.upload is None or row.ping is None
    outage = False
    degraded = False
    if failed:
        outage = thresholds.failed_test_is_outage
    else:
        outage = bool(
            row.download < thresholds.outage_download_mbps or row.ping > thresholds.high_ping_ms
        )
        degraded = bool(
            not outage
            and row.download >= thresholds.outage_download_mbps
            and row.download < thresholds.degraded_download_mbps
        )
    row.is_failed = failed
    row.is_outage = outage
    row.is_degraded = degraded
    if failed:
        row.status = "failed"
    elif outage:
        row.status = "outage"
    elif degraded:
        row.status = "degraded"
    else:
        row.status = "normal"
    return row


def _merge_history(history: dict[str, list[dict[str, Any]]], now: datetime, days: int = 30) -> list[DashboardRow]:
    download_points = history_points_for_window(history, "download", now - timedelta(days=days))
    upload_points = history_points_for_window(history, "upload", now - timedelta(days=days))
    ping_points = history_points_for_window(history, "ping", now - timedelta(days=days))

    merged: dict[str, DashboardRow] = {}
    for metric_name, points in [("download", download_points), ("upload", upload_points), ("ping", ping_points)]:
        for moment, value in points:
            key = moment.isoformat()
            row = merged.get(key)
            if row is None:
                row = DashboardRow(timestamp=moment, download=None, upload=None, ping=None)
                merged[key] = row
            setattr(row, metric_name, value)
    return sorted(merged.values(), key=lambda row: row.timestamp)


def _rows_from_run_records(
    run_rows: list[dict[str, Any]] | None,
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    thresholds: DashboardThresholds,
    days: int = 30,
) -> list[DashboardRow]:
    if not run_rows:
        return [_classify_row(row, thresholds) for row in _merge_history(history, now, days=days)]
    rows: list[DashboardRow] = []
    cutoff = now - timedelta(days=days)
    for item in run_rows:
        recorded_at = _coerce_datetime(item.get("recorded_at"))
        if recorded_at is None or recorded_at < cutoff:
            continue
        rows.append(
            _classify_row(
                DashboardRow(
                    timestamp=recorded_at,
                    download=_safe_float(item.get("download_mbps")),
                    upload=_safe_float(item.get("upload_mbps")),
                    ping=_safe_float(item.get("ping_ms")),
                    speed_ok=bool(item.get("speed_ok", True)),
                    speed_summary=str(item.get("speed_summary") or ""),
                    speed_warnings=str(item.get("speed_warnings") or ""),
                ),
                thresholds,
            )
        )
    return sorted(rows, key=lambda row: row.timestamp)


def _load_router_events(config: AppConfig | None) -> list[RouterEvent]:
    if config is None:
        return []
    csv_path = Path(config.router_events_csv)
    json_path = Path(config.router_events_json)
    rows: list[RouterEvent] = []
    if csv_path.exists():
        try:
            with csv_path.open("r", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for item in reader:
                    timestamp = _coerce_datetime(item.get("timestamp") or item.get("datetime"))
                    if timestamp is None:
                        continue
                    rows.append(
                        RouterEvent(
                            timestamp=timestamp,
                            event_type=str(item.get("event_type") or "event"),
                            message=str(item.get("message") or ""),
                            severity=str(item.get("severity") or "info"),
                            source=str(item.get("source") or ""),
                        )
                    )
        except OSError:
            return []
    elif json_path.exists():
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            timestamp = _coerce_datetime(item.get("timestamp") or item.get("datetime"))
            if timestamp is None:
                continue
            rows.append(
                RouterEvent(
                    timestamp=timestamp,
                    event_type=str(item.get("event_type") or "event"),
                    message=str(item.get("message") or ""),
                    severity=str(item.get("severity") or "info"),
                    source=str(item.get("source") or ""),
                )
            )
    return sorted(rows, key=lambda event: event.timestamp)


def _load_pihole_hourly_rows(config: AppConfig | None) -> list[PiholeHourlyRow]:
    if config is None:
        return []
    path = Path(config.pihole_hourly_csv)
    if not path.exists():
        return []
    rows: list[PiholeHourlyRow] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for item in reader:
                timestamp = _coerce_datetime(item.get("datetime") or item.get("hour"))
                if timestamp is None:
                    continue
                rows.append(
                    PiholeHourlyRow(
                        timestamp=timestamp,
                        dns_queries=_safe_float(item.get("dns_queries")),
                        blocked_queries=_safe_float(item.get("blocked_queries")),
                        blocked_percent=_safe_float(item.get("blocked_percent")),
                    )
                )
    except OSError:
        return []
    return sorted(rows, key=lambda row: row.timestamp)


def _hour_label(hour: int | None) -> str:
    if hour is None:
        return "n/a"
    return f"{hour:02d}:00"


def _streaks(rows: list[DashboardRow]) -> tuple[int, str]:
    longest = 0
    current = 0
    worst_start: datetime | None = None
    current_start: datetime | None = None
    worst_end: datetime | None = None
    for row in rows:
        if row.is_outage or row.is_failed:
            current += 1
            if current_start is None:
                current_start = row.timestamp
            if current > longest:
                longest = current
                worst_start = current_start
                worst_end = row.timestamp
        else:
            current = 0
            current_start = None
    if longest and worst_start is not None and worst_end is not None:
        return longest, f"{worst_start.strftime('%d %b %H:%M')} – {worst_end.strftime('%d %b %H:%M')}"
    return 0, "No outage window recorded"


def _score_breakdown(rows: list[DashboardRow], thresholds: DashboardThresholds) -> dict[str, Any]:
    valid_rows = [row for row in rows if not row.is_failed and row.download is not None and row.upload is not None and row.ping is not None]
    downloads = [row.download for row in valid_rows if row.download is not None]
    uploads = [row.upload for row in valid_rows if row.upload is not None]
    pings = [row.ping for row in valid_rows if row.ping is not None]
    valid_count = len(valid_rows)
    pct_meeting = (
        sum(1 for value in downloads if value >= thresholds.degraded_download_mbps) / len(downloads) * 100.0
        if downloads
        else 0.0
    )
    median_down = _quantile(downloads, 0.5) or 0.0
    speed_score = min(20.0, pct_meeting / 5.0) + min(20.0, (median_down / max(thresholds.heatmap_good_mbps, 1.0)) * 20.0)

    avg_up = average(uploads) or 0.0
    up_p95 = _quantile(uploads, 0.95) or avg_up
    upload_consistency = 1.0 if up_p95 <= 0 else max(0.0, min(1.0, avg_up / up_p95))
    upload_score = min(12.0, avg_up / 4.0) + (upload_consistency * 8.0)

    avg_ping = average(pings) or 0.0
    ping_p95 = _quantile(pings, 0.95) or avg_ping
    latency_score = max(0.0, 12.0 - max(avg_ping - 3.0, 0.0) * 0.6) + max(0.0, 8.0 - max(ping_p95 - thresholds.high_ping_ms, 0.0) * 0.35)

    failed_count = sum(1 for row in rows if row.is_failed)
    outage_count = sum(1 for row in rows if row.is_outage)
    degraded_count = sum(1 for row in rows if row.is_degraded)
    penalty = 0.0
    total = max(len(rows), 1)
    penalty += (failed_count / total) * 14.0
    penalty += (outage_count / total) * 10.0
    penalty += (degraded_count / total) * 6.0
    stability_score = max(0.0, 20.0 - penalty)

    speed_score = round(max(0.0, min(40.0, speed_score)), 1)
    upload_score = round(max(0.0, min(20.0, upload_score)), 1)
    latency_score = round(max(0.0, min(20.0, latency_score)), 1)
    stability_score = round(max(0.0, min(20.0, stability_score)), 1)
    total_score = round(speed_score + upload_score + latency_score + stability_score, 1)
    return {
        "speed": speed_score,
        "upload": upload_score,
        "latency": latency_score,
        "stability": stability_score,
        "total": total_score,
        "explanation": [
            f"Speed score combines median download and the share of valid tests at or above {thresholds.degraded_download_mbps:.0f} Mbps.",
            "Upload score combines average upload and how tightly upload results cluster.",
            f"Latency score rewards low average ping and low 95th percentile ping, with {thresholds.high_ping_ms:.0f} ms as the high-ping threshold.",
            "Stability score penalises failed tests, outage-classified tests, and degraded tests.",
        ],
        "valid_tests": valid_count,
    }


def _build_dashboard_payload(
    rows: list[DashboardRow],
    events: list[RouterEvent],
    pihole_rows: list[PiholeHourlyRow],
    thresholds: DashboardThresholds,
    output_path: str,
    public_dashboard_url: str = "",
) -> dict[str, Any]:
    downloads: list[float] = []
    uploads: list[float] = []
    pings: list[float] = []
    data: list[dict[str, Any]] = []
    for row in rows:
        if row.download is not None:
            downloads.append(row.download)
        if row.upload is not None:
            uploads.append(row.upload)
        if row.ping is not None:
            pings.append(row.ping)
        data.append(
            {
                "datetime": row.timestamp.isoformat(),
                "label": row.timestamp.strftime("%a %d %b %Y %H:%M"),
                "date": row.timestamp.strftime("%Y-%m-%d"),
                "time": row.timestamp.strftime("%H:%M"),
                "hour": row.timestamp.hour,
                "day": row.timestamp.strftime("%A"),
                "dow": row.timestamp.weekday(),
                "download": row.download,
                "upload": row.upload,
                "ping": row.ping,
                "status": row.status,
                "isFailed": row.is_failed,
                "isOutage": row.is_outage,
                "isDegraded": row.is_degraded,
                "speedOk": row.speed_ok,
                "speedSummary": row.speed_summary,
            }
        )

    start = rows[0].timestamp.strftime("%d %b %Y") if rows else "n/a"
    end = rows[-1].timestamp.strftime("%d %b %Y") if rows else "n/a"
    p05 = _quantile(downloads, 0.05)
    p95 = _quantile(downloads, 0.95)
    pct_threshold = (
        sum(1 for value in downloads if value >= thresholds.degraded_download_mbps) / len(downloads) * 100.0
        if downloads
        else 0.0
    )
    failed_count = sum(1 for row in rows if row.is_failed)
    outage_count = sum(1 for row in rows if row.is_outage)
    degraded_count = sum(1 for row in rows if row.is_degraded)
    longest_outage_streak, worst_window = _streaks(rows)

    hourly_values: list[list[float]] = [[] for _ in range(24)]
    for row in rows:
        if row.download is not None:
            hourly_values[row.timestamp.hour].append(row.download)
    hour_avg = [average(values) if values else None for values in hourly_values]
    best_hour = max(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)
    slow_hour = min(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)

    latest = rows[-1] if rows else None
    score = _score_breakdown(rows, thresholds)
    legacy_score = _score_connection(average(downloads), average(uploads), average(pings), pct_threshold)

    if latest is None:
        verdict = "no_data"
        verdict_label = "No data yet"
    elif latest.is_failed:
        verdict = "failed"
        verdict_label = "Latest test failed"
    elif latest.is_outage:
        verdict = "outage"
        verdict_label = "Outage indicators detected"
    elif latest.is_degraded:
        verdict = "degraded"
        verdict_label = "Connection below usual target"
    else:
        verdict = "normal"
        verdict_label = "Connection looks healthy"

    event_data = [
        {
            "datetime": event.timestamp.isoformat(),
            "time": event.timestamp.strftime("%d %b %Y %H:%M"),
            "eventType": event.event_type,
            "message": event.message,
            "severity": event.severity,
            "source": event.source,
        }
        for event in events[-200:]
    ]
    pihole_data = [
        {
            "datetime": row.timestamp.isoformat(),
            "hour": row.timestamp.strftime("%d %b %H:%M"),
            "dnsQueries": row.dns_queries,
            "blockedQueries": row.blocked_queries,
            "blockedPercent": row.blocked_percent,
        }
        for row in pihole_rows
    ]

    metadata = {
        "service": SERVICE_NAME,
        "generated_at": datetime.now().astimezone().isoformat(),
        "dataset_start": rows[0].timestamp.isoformat() if rows else "",
        "dataset_end": rows[-1].timestamp.isoformat() if rows else "",
        "test_count": len(rows),
        "dashboard_path": str(Path(output_path).resolve()),
        "version": _version_string(),
    }

    return {
        "data": data,
        "events": event_data,
        "pihole": pihole_data,
        "stats": {
            "tests": len(rows),
            "start": start,
            "end": end,
            "avgDown": round(average(downloads) or 0.0, 1),
            "medianDown": round(_quantile(downloads, 0.5) or 0.0, 1),
            "avgUp": round(average(uploads) or 0.0, 1),
            "avgPing": round(average(pings) or 0.0, 2),
            "p05": round(p05 or 0.0, 1),
            "p95": round(p95 or 0.0, 1),
            "pctThreshold": round(pct_threshold, 1),
            "thresholdMbps": thresholds.degraded_download_mbps,
            "failedCount": failed_count,
            "outageCount": outage_count,
            "degradedCount": degraded_count,
            "longestOutageStreak": longest_outage_streak,
            "worstWindow": worst_window,
            "bestHour": _hour_label(best_hour[0]) if best_hour else "n/a",
            "bestHourMbps": round(best_hour[1], 1) if best_hour else None,
            "slowHour": _hour_label(slow_hour[0]) if slow_hour else "n/a",
            "slowHourMbps": round(slow_hour[1], 1) if slow_hour else None,
            "legacyScore": legacy_score,
            "publicDashboardUrl": public_dashboard_url,
            "latestStatus": latest.status if latest else "none",
            "latestDownload": latest.download if latest else None,
            "latestUpload": latest.upload if latest else None,
            "latestPing": latest.ping if latest else None,
            "verdict": verdict,
            "verdictLabel": verdict_label,
        },
        "score": score,
        "thresholds": {
            "outageDownloadMbps": thresholds.outage_download_mbps,
            "degradedDownloadMbps": thresholds.degraded_download_mbps,
            "highPingMs": thresholds.high_ping_ms,
            "failedTestIsOutage": thresholds.failed_test_is_outage,
            "heatmapGoodMbps": thresholds.heatmap_good_mbps,
            "heatmapWarnMbps": thresholds.heatmap_warn_mbps,
        },
        "meta": metadata,
    }


def build_dashboard_summary(
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    config: AppConfig | None = None,
    run_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    thresholds = _build_thresholds(config)
    rows = _rows_from_run_records(run_rows, history, now, thresholds, days=30)
    payload = _build_dashboard_payload(rows, [], [], thresholds, output_path="dashboard.html", public_dashboard_url=(config.public_dashboard_url if config else ""))
    return {
        "stats": payload["stats"],
        "score": payload["score"],
        "thresholds": payload["thresholds"],
    }


def generate_interactive_dashboard(
    history: dict[str, list[dict[str, Any]]],
    now: datetime,
    output_path: str,
    config: AppConfig | None = None,
    run_rows: list[dict[str, Any]] | None = None,
    router_events: list[RouterEvent] | None = None,
    pihole_rows: list[PiholeHourlyRow] | None = None,
) -> tuple[bool, str]:
    thresholds = _build_thresholds(config)
    rows = _rows_from_run_records(run_rows, history, now, thresholds, days=30)
    if not rows:
        return False, "No speed data available for interactive dashboard"

    event_rows = router_events if router_events is not None else _load_router_events(config)
    dns_rows = pihole_rows if pihole_rows is not None else _load_pihole_hourly_rows(config)
    payload = _build_dashboard_payload(
        rows,
        event_rows,
        dns_rows,
        thresholds,
        output_path=output_path,
        public_dashboard_url=(config.public_dashboard_url if config else ""),
    )
    html = _render_interactive_dashboard_html(payload)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    output.with_name(STATUS_FILE_NAME).write_text(json.dumps(payload["meta"], indent=2), encoding="utf-8")
    return True, f"Interactive dashboard written to {output}"


def _render_interactive_dashboard_html(payload: dict[str, Any]) -> str:
    payload_json = json.dumps(payload)
    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pi Probe NBN Interactive Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
:root {
  --bg: #07101c;
  --panel: rgba(16, 24, 39, 0.88);
  --panel-2: rgba(12, 20, 33, 0.72);
  --border: rgba(148, 163, 184, 0.18);
  --text: #f8fafc;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --accent-2: #22c55e;
  --warn: #f59e0b;
  --danger: #ef4444;
}
body.theme-clean {
  --bg: #e8eef7;
  --panel: rgba(255,255,255,.92);
  --panel-2: rgba(255,255,255,.84);
  --border: rgba(30, 41, 59, .12);
  --text: #0f172a;
  --muted: #475569;
  --accent: #0284c7;
  --accent-2: #15803d;
  --warn: #d97706;
  --danger: #dc2626;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--text);
  background:
    radial-gradient(circle at top left, rgba(56,189,248,.18), transparent 28rem),
    radial-gradient(circle at top right, rgba(34,197,94,.12), transparent 26rem),
    linear-gradient(180deg, #020617, var(--bg));
  min-height: 100vh;
}
body.theme-clean { background: linear-gradient(180deg, #f8fafc, var(--bg)); }
.wrap { max-width: 1560px; margin: 0 auto; padding: 24px; }
.hero { display:grid; grid-template-columns: 1.2fr .8fr; gap: 18px; margin-bottom: 18px; }
.hero, .panel, .kpi { backdrop-filter: blur(12px); }
.panel, .kpi, .controls {
  border: 1px solid var(--border);
  background: var(--panel);
  border-radius: 22px;
  box-shadow: 0 24px 70px rgba(0,0,0,.18);
}
.hero-main { padding: 20px 22px; }
.hero-main h1 { margin: 0; font-size: clamp(28px, 4vw, 48px); letter-spacing: -.04em; }
.hero-main .sub { margin-top: 6px; color: var(--muted); font-size: 15px; }
.hero-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 18px; }
.kpi { padding: 16px; min-height: 112px; }
.kpi .label { color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.kpi .value { margin-top: 10px; font-size: 30px; font-weight: 900; letter-spacing: -.05em; }
.kpi .sub { margin-top: 8px; color: var(--muted); font-size: 12px; line-height: 1.35; }
.hero-side { padding: 20px 22px; display:flex; flex-direction:column; gap: 14px; }
.hero-side .verdict { font-size: 22px; font-weight: 900; letter-spacing: -.03em; }
.hero-side .copy { color: var(--muted); font-size: 14px; line-height: 1.45; }
.hero-side .chiprow { display:flex; flex-wrap:wrap; gap: 10px; }
.chip { padding: 9px 12px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); font-size: 13px; }
.controls { display:grid; grid-template-columns: repeat(6, 1fr); gap: 12px; padding: 14px; margin-bottom: 18px; }
label { display:block; color: var(--muted); font-size: 12px; font-weight: 700; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .06em; }
select, input { width: 100%; border: 1px solid var(--border); background: rgba(2,6,23,.28); color: var(--text); border-radius: 12px; padding: 10px 11px; }
body.theme-clean select, body.theme-clean input { background: rgba(255,255,255,.72); }
.grid { display:grid; grid-template-columns: 1.65fr .9fr; gap: 18px; }
.stack { display:grid; gap: 18px; }
.panel { padding: 18px; }
.panel-head { margin-bottom: 12px; }
.panel-head h2 { margin: 0; font-size: 24px; letter-spacing: -.03em; }
.panel-head p { margin: 4px 0 0; color: var(--muted); font-size: 13px; line-height: 1.4; }
.chart { height: 390px; }
.chart-small { height: 320px; }
.table-wrap { overflow:auto; border-radius: 16px; border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.score-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px; }
.score-card { padding: 14px; border: 1px solid var(--border); border-radius: 16px; background: var(--panel-2); }
.score-card b { display:block; font-size: 26px; margin-top: 6px; }
.note-list { margin: 0; padding-left: 18px; color: var(--muted); font-size: 13px; line-height: 1.45; }
.empty { color: var(--muted); font-size: 14px; padding: 18px; border: 1px dashed var(--border); border-radius: 16px; }
.linkline { margin-top: auto; }
.linkline a { color: var(--accent); text-decoration: none; font-weight: 700; }
@media (max-width: 1180px) {
  .hero, .grid, .controls, .hero-grid, .score-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <div class="hero-main panel">
      <h1>Pi Probe Interactive Dashboard</h1>
      <div class="sub" id="subtitle"></div>
      <div class="hero-grid">
        <div class="kpi"><div class="label">Median download</div><div class="value" id="kpiMedian"></div><div class="sub">Typical observed downstream performance</div></div>
        <div class="kpi"><div class="label">Average upload</div><div class="value" id="kpiUpload"></div><div class="sub">Mean upload across visible tests</div></div>
        <div class="kpi"><div class="label">Average ping</div><div class="value" id="kpiPing"></div><div class="sub">Mean latency across visible tests</div></div>
        <div class="kpi"><div class="label">Reliability floor</div><div class="value" id="kpiFloor"></div><div class="sub">5th percentile download result</div></div>
      </div>
    </div>
    <div class="hero-side panel">
      <div class="verdict" id="verdict"></div>
      <div class="copy" id="verdictCopy"></div>
      <div class="chiprow">
        <div class="chip" id="kpiThreshold"></div>
        <div class="chip" id="kpiFailed"></div>
        <div class="chip" id="kpiOutage"></div>
        <div class="chip" id="kpiDegraded"></div>
        <div class="chip" id="kpiStreak"></div>
      </div>
      <div class="copy" id="worstWindow"></div>
      <div class="linkline" id="dashboardLinkWrap"></div>
    </div>
  </section>

  <section class="controls">
    <div><label>Metric</label><select id="metric"><option value="download">Download Mbps</option><option value="upload">Upload Mbps</option><option value="ping">Ping ms</option></select></div>
    <div><label>Minimum speed threshold</label><input id="threshold" type="number" min="0" step="10"></div>
    <div><label>Day filter</label><select id="dayFilter"><option value="all">All days</option><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option><option>Saturday</option><option>Sunday</option></select></div>
    <div><label>Event severity</label><select id="severityFilter"></select></div>
    <div><label>Event type</label><select id="eventTypeFilter"></select></div>
    <div><label>Theme</label><select id="theme"><option value="auto">Auto / system</option><option value="premium">Premium dark</option><option value="clean">Clean light</option></select></div>
  </section>

  <section class="grid">
    <div class="stack">
      <div class="panel">
        <div class="panel-head"><h2>Performance Timeline</h2><p>Normal, degraded, outage, and failed tests are separated. Router event markers can be filtered by severity and type.</p></div>
        <div id="timeline" class="chart"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Recent Router and Network Events</h2><p>Most recent 20 imported events from the optional router events file.</p></div>
        <div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Message</th></tr></thead><tbody id="eventRows"></tbody></table></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>DNS Activity Correlation</h2><p>Hourly DNS load and blocked requests plotted against average download when Pi-hole hourly data exists.</p></div>
        <div id="dnsCorrelation" class="chart-small"></div>
        <div id="dnsEmpty" class="empty" style="display:none">No Pi-hole hourly data yet.</div>
      </div>
    </div>
    <div class="stack">
      <div class="panel">
        <div class="panel-head"><h2>Traffic-Light Heatmap</h2><p>Hourly average download. Green exceeds the good threshold, amber is acceptable, red is below target.</p></div>
        <div id="heatmap" class="chart-small"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Latency Relationship</h2><p>Scatter of download versus ping. Failed, degraded, and outage tests are emphasised.</p></div>
        <div id="scatter" class="chart-small"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Score Breakdown</h2><p>Explainable score with speed, upload, latency, and stability components.</p></div>
        <div class="score-grid">
          <div class="score-card"><div class="label">Speed</div><b id="scoreSpeed"></b></div>
          <div class="score-card"><div class="label">Upload</div><b id="scoreUpload"></b></div>
          <div class="score-card"><div class="label">Latency</div><b id="scoreLatency"></b></div>
          <div class="score-card"><div class="label">Stability</div><b id="scoreStability"></b></div>
        </div>
        <div class="score-card" style="margin-bottom:12px"><div class="label">Total quality score</div><b id="scoreTotal"></b></div>
        <ul class="note-list" id="scoreNotes"></ul>
      </div>
    </div>
  </section>
</div>
<script>
const payload = __PAYLOAD_JSON__;
const rawData = payload.data;
const rawEvents = payload.events;
const piholeRows = payload.pihole;
const stats = payload.stats;
const score = payload.score;
const thresholds = payload.thresholds;
const meta = payload.meta;
const themeKey = 'pi_probe_dashboard_theme';

function average(values) {
  const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v));
  return clean.length ? clean.reduce((a, b) => a + b, 0) / clean.length : 0;
}
function quantile(values, q) {
  const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v)).sort((a,b)=>a-b);
  if (!clean.length) return null;
  if (clean.length === 1) return clean[0];
  const pos = (clean.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  return clean[base + 1] !== undefined ? clean[base] + rest * (clean[base + 1] - clean[base]) : clean[base];
}
function getThemeChoice() { return localStorage.getItem(themeKey) || 'auto'; }
function resolveDarkMode(choice) {
  if (choice === 'premium') return true;
  if (choice === 'clean') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}
function applyTheme(choice) {
  localStorage.setItem(themeKey, choice);
  const dark = resolveDarkMode(choice);
  document.body.classList.toggle('theme-clean', !dark);
  render();
}
function layoutBase() {
  const dark = !document.body.classList.contains('theme-clean');
  return {
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',
    font: { color: dark ? '#dbeafe' : '#0f172a', family: 'Inter, system-ui, sans-serif' },
    margin: { l: 48, r: 22, t: 18, b: 48 },
    xaxis: { gridcolor: dark ? 'rgba(148,163,184,.10)' : 'rgba(15,23,42,.10)' },
    yaxis: { gridcolor: dark ? 'rgba(148,163,184,.10)' : 'rgba(15,23,42,.10)' },
    hoverlabel: { bgcolor: dark ? '#0f172a' : '#ffffff', bordercolor: '#38bdf8', font: { color: dark ? '#f8fafc' : '#0f172a' } },
    showlegend: true,
    legend: { orientation: 'h', yanchor: 'bottom', y: 1.02, x: 0 }
  };
}
function initFilters() {
  const severitySelect = document.getElementById('severityFilter');
  const typeSelect = document.getElementById('eventTypeFilter');
  const severities = ['all', ...new Set(rawEvents.map(e => e.severity || 'info'))];
  const types = ['all', ...new Set(rawEvents.map(e => e.eventType || 'event'))];
  severitySelect.innerHTML = severities.map(value => `<option value="${value}">${value === 'all' ? 'All severities' : value}</option>`).join('');
  typeSelect.innerHTML = types.map(value => `<option value="${value}">${value === 'all' ? 'All types' : value}</option>`).join('');
}
function filteredData() {
  const day = document.getElementById('dayFilter').value;
  return rawData.filter(item => day === 'all' || item.day === day);
}
function filteredEvents() {
  const severity = document.getElementById('severityFilter').value;
  const eventType = document.getElementById('eventTypeFilter').value;
  return rawEvents.filter(item => (severity === 'all' || item.severity === severity) && (eventType === 'all' || item.eventType === eventType));
}
function renderTable(events) {
  const body = document.getElementById('eventRows');
  if (!events.length) {
    body.innerHTML = '<tr><td colspan="5">No matching events.</td></tr>';
    return;
  }
  body.innerHTML = events.slice(-20).reverse().map(event => `<tr><td>${event.time}</td><td>${event.eventType}</td><td>${event.severity}</td><td>${event.source || 'n/a'}</td><td>${event.message || ''}</td></tr>`).join('');
}
function heatmapColorscale() {
  const maxValue = Math.max(thresholds.heatmapGoodMbps * 1.15, ...rawData.map(item => item.download || 0), thresholds.heatmapWarnMbps + 1);
  const warnFrac = Math.min(1, thresholds.heatmapWarnMbps / maxValue);
  const goodFrac = Math.min(1, thresholds.heatmapGoodMbps / maxValue);
  return { colorscale: [
    [0, '#b91c1c'],
    [Math.max(0, warnFrac - 0.0001), '#ef4444'],
    [warnFrac, '#f59e0b'],
    [Math.max(warnFrac, goodFrac - 0.0001), '#facc15'],
    [goodFrac, '#22c55e'],
    [1, '#15803d']
  ], zmax: maxValue };
}
function timelineTraces(data, events, metric) {
  const suffix = metric === 'ping' ? ' ms' : ' Mbps';
  const traces = [{
    x: data.map(d => d.datetime),
    y: data.map(d => d[metric]),
    text: data.map(d => d.label),
    type: 'scatter',
    mode: 'lines',
    name: 'All tests',
    line: { width: 2.4, color: '#38bdf8' },
    hovertemplate: '%{text}<br>' + metric + ': %{y:.2f}' + suffix + '<br>Status: %{customdata}<extra></extra>',
    customdata: data.map(d => d.status)
  }];
  const markerSeries = [
    ['degraded', '#f59e0b', 'Degraded tests'],
    ['outage', '#ef4444', 'Outage tests'],
    ['failed', '#f97316', 'Failed tests']
  ];
  for (const [status, color, label] of markerSeries) {
    const subset = data.filter(item => item.status === status);
    if (!subset.length) continue;
    traces.push({
      x: subset.map(d => d.datetime), y: subset.map(d => d[metric]), text: subset.map(d => d.label),
      type: 'scatter', mode: 'markers', name: label,
      marker: { size: status === 'failed' ? 10 : 9, color, symbol: status === 'failed' ? 'x' : 'circle' },
      hovertemplate: '%{text}<br>' + metric + ': %{y:.2f}' + suffix + '<br>Status: ' + status + '<extra></extra>'
    });
  }
  return traces;
}
function renderTimeline(data, events) {
  const metric = document.getElementById('metric').value;
  const layout = layoutBase();
  layout.yaxis.title = metric === 'ping' ? 'Milliseconds' : 'Mbps';
  layout.shapes = events.map(event => ({
    type: 'line', xref: 'x', yref: 'paper', x0: event.datetime, x1: event.datetime, y0: 0, y1: 1,
    line: { color: event.severity === 'critical' ? '#ef4444' : event.severity === 'warning' ? '#f59e0b' : '#94a3b8', width: 1.2, dash: 'dot' }
  }));
  Plotly.newPlot('timeline', timelineTraces(data, events, metric), layout, { responsive: true, displaylogo: false });
}
function renderHeatmap(data) {
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  const z = days.map(day => Array.from({length:24}, (_,hour) => {
    const values = data.filter(item => item.day === day).filter(item => item.hour === hour).map(item => item.download).filter(v => v !== null);
    return values.length ? average(values) : null;
  }));
  const scale = heatmapColorscale();
  const layout = layoutBase();
  layout.xaxis.title = 'Hour';
  Plotly.newPlot('heatmap', [{
    z, x: Array.from({length:24}, (_,i)=>i), y: days.map(day => day.slice(0,3)), type: 'heatmap',
    colorscale: scale.colorscale, zmin: 0, zmax: scale.zmax,
    colorbar: { title: 'Mbps' },
    hovertemplate: '%{y} %{x}:00<br>Average download: %{z:.1f} Mbps<extra></extra>'
  }], layout, { responsive: true, displaylogo: false });
}
function renderScatter(data) {
  const layout = layoutBase();
  layout.xaxis.title = 'Download Mbps';
  layout.yaxis.title = 'Ping ms';
  const series = [
    ['normal', '#38bdf8', 'Normal'],
    ['degraded', '#f59e0b', 'Degraded'],
    ['outage', '#ef4444', 'Outage'],
    ['failed', '#f97316', 'Failed']
  ].map(([status, color, label]) => {
    const subset = data.filter(item => item.status === status && item.download !== null && item.ping !== null);
    return {
      x: subset.map(item => item.download), y: subset.map(item => item.ping), text: subset.map(item => item.label), type: 'scatter', mode: 'markers',
      name: label, marker: { size: status === 'failed' ? 11 : 8, opacity: .78, color },
      hovertemplate: '%{text}<br>Download: %{x:.2f} Mbps<br>Ping: %{y:.2f} ms<br>Status: ' + status + '<extra></extra>'
    };
  }).filter(trace => trace.x.length);
  Plotly.newPlot('scatter', series, layout, { responsive: true, displaylogo: false });
}
function renderDnsCorrelation(data) {
  const dnsChart = document.getElementById('dnsCorrelation');
  const dnsEmpty = document.getElementById('dnsEmpty');
  if (!piholeRows.length) {
    dnsChart.style.display = 'none';
    dnsEmpty.style.display = 'block';
    return;
  }
  dnsChart.style.display = 'block';
  dnsEmpty.style.display = 'none';
  const hourlyDownload = Array.from({length:24}, (_,hour) => {
    const values = data.filter(item => item.hour === hour).map(item => item.download).filter(v => v !== null);
    return values.length ? average(values) : null;
  });
  const dnsByHour = Array.from({length:24}, (_,hour) => {
    const subset = piholeRows.filter(item => new Date(item.datetime).getHours() === hour);
    return {
      dns: average(subset.map(item => item.dnsQueries)),
      blocked: average(subset.map(item => item.blockedQueries))
    };
  });
  const layout = layoutBase();
  layout.xaxis.title = 'Hour';
  layout.yaxis.title = 'Download Mbps';
  layout.yaxis2 = { title: 'Queries', overlaying: 'y', side: 'right', gridcolor: 'rgba(0,0,0,0)' };
  Plotly.newPlot('dnsCorrelation', [
    { x: Array.from({length:24}, (_,i)=>i), y: hourlyDownload, type: 'scatter', mode: 'lines+markers', name: 'Avg download', line: { color: '#38bdf8', width: 2.5 } },
    { x: Array.from({length:24}, (_,i)=>i), y: dnsByHour.map(item => item.dns), type: 'bar', name: 'DNS queries', yaxis: 'y2', marker: { color: 'rgba(34,197,94,.50)' } },
    { x: Array.from({length:24}, (_,i)=>i), y: dnsByHour.map(item => item.blocked), type: 'bar', name: 'Blocked queries', yaxis: 'y2', marker: { color: 'rgba(245,158,11,.50)' } }
  ], layout, { responsive: true, displaylogo: false });
}
function renderScore() {
  document.getElementById('scoreSpeed').textContent = score.speed.toFixed(1) + ' / 40';
  document.getElementById('scoreUpload').textContent = score.upload.toFixed(1) + ' / 20';
  document.getElementById('scoreLatency').textContent = score.latency.toFixed(1) + ' / 20';
  document.getElementById('scoreStability').textContent = score.stability.toFixed(1) + ' / 20';
  document.getElementById('scoreTotal').textContent = score.total.toFixed(1) + ' / 100';
  document.getElementById('scoreNotes').innerHTML = score.explanation.map(line => `<li>${line}</li>`).join('');
}
function renderSummary(data) {
  const threshold = Number(document.getElementById('threshold').value || thresholds.degradedDownloadMbps);
  const downloads = data.map(item => item.download).filter(v => v !== null);
  document.getElementById('subtitle').textContent = `Interactive history view · dataset ${stats.start} – ${stats.end} · generated ${meta.generated_at}`;
  document.getElementById('kpiMedian').textContent = (quantile(downloads, .5) || 0).toFixed(1) + ' Mbps';
  document.getElementById('kpiUpload').textContent = average(data.map(item => item.upload)).toFixed(1) + ' Mbps';
  document.getElementById('kpiPing').textContent = average(data.map(item => item.ping)).toFixed(2) + ' ms';
  document.getElementById('kpiFloor').textContent = (quantile(downloads, .05) || 0).toFixed(1) + ' Mbps';
  const pct = downloads.length ? downloads.filter(v => v >= threshold).length / downloads.length * 100 : 0;
  document.getElementById('kpiThreshold').textContent = pct.toFixed(1) + `% ≥ ${threshold} Mbps`;
  document.getElementById('kpiFailed').textContent = `${data.filter(item => item.isFailed).length} failed`;
  document.getElementById('kpiOutage').textContent = `${data.filter(item => item.isOutage).length} outage`;
  document.getElementById('kpiDegraded').textContent = `${data.filter(item => item.isDegraded).length} degraded`;
  const longest = (() => {
    let best = 0, current = 0;
    for (const item of data) {
      if (item.isFailed || item.isOutage) { current += 1; best = Math.max(best, current); }
      else { current = 0; }
    }
    return best;
  })();
  document.getElementById('kpiStreak').textContent = `${longest} longest outage streak`;
  document.getElementById('verdict').textContent = stats.verdictLabel;
  document.getElementById('verdictCopy').textContent = `Latest result: ${stats.latestDownload ?? 'n/a'} Mbps down, ${stats.latestUpload ?? 'n/a'} Mbps up, ${stats.latestPing ?? 'n/a'} ms ping.`;
  document.getElementById('worstWindow').textContent = `Worst window: ${stats.worstWindow}`;
  const linkWrap = document.getElementById('dashboardLinkWrap');
  linkWrap.innerHTML = stats.publicDashboardUrl ? `<a href="${stats.publicDashboardUrl}" target="_blank" rel="noreferrer">Open public dashboard</a>` : '';
}
function render() {
  const data = filteredData();
  const events = filteredEvents();
  renderSummary(data);
  renderTimeline(data, events);
  renderHeatmap(data);
  renderScatter(data);
  renderDnsCorrelation(data);
  renderTable(events);
  renderScore();
}
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (getThemeChoice() === 'auto') applyTheme('auto'); });
document.getElementById('theme').value = getThemeChoice();
document.getElementById('theme').addEventListener('change', event => applyTheme(event.target.value));
document.getElementById('metric').addEventListener('change', render);
document.getElementById('threshold').value = stats.thresholdMbps;
document.getElementById('threshold').addEventListener('input', render);
document.getElementById('dayFilter').addEventListener('change', render);
document.getElementById('severityFilter').addEventListener('change', render);
document.getElementById('eventTypeFilter').addEventListener('change', render);
initFilters();
applyTheme(getThemeChoice());
</script>
</body>
</html>
"""
    return template.replace('__PAYLOAD_JSON__', payload_json)


def generate_premium_dashboard(history: dict[str, list[dict[str, Any]]], now: datetime, chart_path: str, speed_result: SpeedResult) -> tuple[bool, str]:
    if plt is None or mdates is None:
        return False, "matplotlib not installed"

    rows = _merge_history(history, now, days=30)
    if not rows:
        return False, "No speed data available for premium dashboard"

    data_rows = [
        {"recorded_at": row.timestamp.isoformat(), "speed_ok": True, "download_mbps": row.download, "upload_mbps": row.upload, "ping_ms": row.ping}
        for row in rows
    ]
    thresholds = _build_thresholds(None)
    classified_rows = _rows_from_run_records(data_rows, history, now, thresholds, days=30)
    payload = _build_dashboard_payload(classified_rows, [], [], thresholds, output_path=chart_path)
    stats = payload["stats"]
    figure = plt.figure(figsize=(16, 10), facecolor="#111827")
    gs = figure.add_gridspec(3, 12, height_ratios=[1.0, 2.2, 2.0], hspace=0.28, wspace=0.42)

    figure.text(0.04, 0.95, "Internet Health Snapshot", color="#f8fafc", fontsize=26, fontweight="bold", ha="left", va="top")
    figure.text(
        0.04,
        0.915,
        f"Local history · {stats['start']} – {stats['end']} · {stats['tests']} tests",
        color="#94a3b8",
        fontsize=13,
        ha="left",
        va="top",
    )

    cards = [
        ("Typical download", f"{stats['medianDown']:.0f} Mbps", f"Average {stats['avgDown']:.0f} Mbps"),
        ("Average upload", f"{stats['avgUp']:.1f} Mbps", f"{stats['pctThreshold']:.0f}% ≥ {thresholds.degraded_download_mbps:.0f} Mbps"),
        ("Average ping", f"{stats['avgPing']:.1f} ms", f"Reliability floor {stats['p05']:.0f} Mbps"),
        ("Quality score", f"{payload['score']['total']:.0f}/100", f"Failed {stats['failedCount']} · outage {stats['outageCount']} · degraded {stats['degradedCount']}"),
    ]
    for idx, (title, value, subtitle) in enumerate(cards):
        ax = figure.add_subplot(gs[0, idx * 12 // 4 : (idx + 1) * 12 // 4])
        ax.set_facecolor("#152033")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.text(0.06, 0.74, title, transform=ax.transAxes, color="#cbd5e1", fontsize=12, fontweight="bold", ha="left")
        ax.text(0.06, 0.40, value, transform=ax.transAxes, color="#f8fafc", fontsize=27, fontweight="bold", ha="left")
        ax.text(0.06, 0.18, subtitle, transform=ax.transAxes, color="#94a3b8", fontsize=10.5, ha="left")

    def style_panel(ax: Any, title: str, subtitle: str | None = None) -> Any:
        ax.set_facecolor("#152033")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.text(0.04, 0.94, title, transform=ax.transAxes, color="#f8fafc", fontsize=16.5, fontweight="bold", ha="left", va="top")
        if subtitle:
            ax.text(0.04, 0.86, subtitle, transform=ax.transAxes, color="#94a3b8", fontsize=10, ha="left", va="top")
        inner = ax.inset_axes([0.05, 0.12, 0.90, 0.68])
        inner.set_facecolor("#152033")
        inner.grid(color="#334155", linewidth=0.8, alpha=0.65)
        inner.tick_params(colors="#cbd5e1", labelsize=10)
        for spine in inner.spines.values():
            spine.set_color("#334155")
        return inner

    by_day: dict[str, list[float]] = {}
    for row in classified_rows:
        if row.download is None:
            continue
        by_day.setdefault(row.timestamp.strftime("%Y-%m-%d"), []).append(row.download)
    day_dates = [datetime.fromisoformat(day) for day in sorted(by_day)]
    day_median = [_quantile(by_day[day.strftime("%Y-%m-%d")], 0.5) or 0.0 for day in day_dates]
    day_average = [average(by_day[day.strftime("%Y-%m-%d")]) or 0.0 for day in day_dates]
    day_low = [min(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]
    day_high = [max(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]

    ax_band_panel = figure.add_subplot(gs[1, :7])
    ax_band = style_panel(ax_band_panel, "Daily Download Reliability Band", "Median, average, and spread across the last 30 days.")
    ax_band.fill_between(day_dates, day_low, day_high, color="#1d4ed8", alpha=0.18)
    ax_band.plot(day_dates, day_median, color="#38bdf8", linewidth=2.4, label="Median")
    ax_band.plot(day_dates, day_average, color="#fb923c", linewidth=1.6, linestyle="--", label="Average")
    ax_band.set_ylabel("Mbps", color="#cbd5e1")
    band_locator = mdates.AutoDateLocator(minticks=4, maxticks=6)
    ax_band.xaxis.set_major_locator(band_locator)
    ax_band.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    ax_band.xaxis.get_offset_text().set_visible(False)
    ax_band.legend(loc="lower right", frameon=False, labelcolor="#cbd5e1")

    heat_values = [[None for _ in range(24)] for _ in range(7)]
    for dow_idx, day_name in enumerate(DAY_NAMES):
        for hour in range(24):
            hour_values = [
                row.download for row in classified_rows
                if row.download is not None and row.timestamp.strftime("%A") == day_name and row.timestamp.hour == hour
            ]
            heat_values[dow_idx][hour] = average(hour_values)
    ax_heat_panel = figure.add_subplot(gs[1, 7:])
    ax_heat = style_panel(ax_heat_panel, "Traffic-Light Speed Heatmap", "Average download by weekday and hour.")
    image = ax_heat.imshow(heat_values, aspect="auto", cmap="viridis")
    ax_heat.set_yticks(range(7), [name[:3] for name in DAY_NAMES], color="#cbd5e1")
    ax_heat.set_xticks(range(0, 24, 3))
    ax_heat.set_xticklabels([str(hour) for hour in range(0, 24, 3)], color="#cbd5e1")
    cbar = figure.colorbar(image, ax=ax_heat, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(colors="#cbd5e1")

    hourly_values: list[list[float]] = [[] for _ in range(24)]
    for row in classified_rows:
        if row.download is not None:
            hourly_values[row.timestamp.hour].append(row.download)
    hour_avg = [average(values) if values else None for values in hourly_values]
    hour_low = [min(values) if values else None for values in hourly_values]
    hour_high = [max(values) if values else None for values in hourly_values]
    valid_hours = [hour for hour, value in enumerate(hour_avg) if value is not None]
    valid_avg = [hour_avg[hour] for hour in valid_hours]
    valid_low = [hour_low[hour] for hour in valid_hours]
    valid_high = [hour_high[hour] for hour in valid_hours]

    ax_times_panel = figure.add_subplot(gs[2, :7])
    ax_times = style_panel(ax_times_panel, "Best and Slowest Times of Day", "Hourly average with low/high spread.")
    ax_times.fill_between(valid_hours, valid_low, valid_high, color="#1d4ed8", alpha=0.18)
    ax_times.plot(valid_hours, valid_avg, color="#38bdf8", linewidth=2.4)
    if valid_avg:
        best_hour_index = valid_hours[max(range(len(valid_avg)), key=lambda idx: valid_avg[idx])]
        slow_hour_index = valid_hours[min(range(len(valid_avg)), key=lambda idx: valid_avg[idx])]
        ax_times.scatter([best_hour_index], [hour_avg[best_hour_index]], color="#22c55e", s=60, zorder=5)
        ax_times.scatter([slow_hour_index], [hour_avg[slow_hour_index]], color="#f97316", s=60, zorder=5)
    ax_times.set_xlabel("Hour of day", color="#cbd5e1")
    ax_times.set_ylabel("Mbps", color="#cbd5e1")
    ax_times.xaxis.set_major_locator(mticker.MultipleLocator(2))

    ax_exec = figure.add_subplot(gs[2, 7:])
    ax_exec.set_facecolor("#152033")
    ax_exec.set_xticks([])
    ax_exec.set_yticks([])
    for spine in ax_exec.spines.values():
        spine.set_visible(False)
    ax_exec.text(0.04, 0.92, "What Stands Out", transform=ax_exec.transAxes, color="#f8fafc", fontsize=17, fontweight="bold", ha="left")
    lines = [
        f"• Typical result: {stats['medianDown']:.0f} Mbps down",
        f"• Reliability floor: {stats['p05']:.0f} Mbps",
        f"• Peak band: {stats['p95']:.0f} Mbps",
        f"• Failed tests: {stats['failedCount']}",
        f"• Outage-classified tests: {stats['outageCount']}",
        f"• Longest outage streak: {stats['longestOutageStreak']}",
    ]
    for idx, line in enumerate(lines):
        ax_exec.text(0.06, 0.80 - idx * 0.10, line, transform=ax_exec.transAxes, color="#cbd5e1", fontsize=12.2, ha="left")

    figure.text(
        0.04,
        0.025,
        "Shaded bands show normal variation. Heatmap shows recurring time-of-day patterns. Quality score is explainable in the interactive dashboard.",
        color="#94a3b8",
        fontsize=10,
        ha="left",
    )

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Premium dashboard generated"


def _version_string() -> str:
    try:
        return importlib_metadata.version("pi-probe-discord")
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


def serve_interactive_dashboard(output_path: str, host: str, port: int) -> int:
    file_path = Path(output_path).resolve()
    directory = file_path.parent
    status_path = directory / STATUS_FILE_NAME

    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(directory), **kwargs)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                payload = b"ok\n"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/status.json":
                try:
                    payload = status_path.read_bytes()
                except OSError:
                    payload = json.dumps(
                        {
                            "service": SERVICE_NAME,
                            "generated_at": "",
                            "dataset_start": "",
                            "dataset_end": "",
                            "test_count": 0,
                            "dashboard_path": str(file_path),
                            "version": _version_string(),
                        }
                    ).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path in {"/", ""}:
                self.path = f"/{file_path.name}"
            return super().do_GET()

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Serving interactive dashboard at http://{host}:{port}/{file_path.name}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
