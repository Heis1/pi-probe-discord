from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
from typing import Any

from .baselines import average, calculate_same_time_baseline, history_points_for_window, min_max
from .models import SpeedResult

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


@dataclass
class DashboardRow:
    timestamp: datetime
    download: float | None
    upload: float | None
    ping: float | None


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


def _build_dashboard_payload(rows: list[DashboardRow]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data: list[dict[str, Any]] = []
    downloads: list[float] = []
    uploads: list[float] = []
    pings: list[float] = []

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
            }
        )

    start = rows[0].timestamp.strftime("%d %b %Y") if rows else "n/a"
    end = rows[-1].timestamp.strftime("%d %b %Y") if rows else "n/a"
    p05 = _quantile(downloads, 0.05)
    p95 = _quantile(downloads, 0.95)
    pct250 = (sum(1 for value in downloads if value >= 250.0) / len(downloads) * 100.0) if downloads else 0.0
    pct300 = (sum(1 for value in downloads if value >= 300.0) / len(downloads) * 100.0) if downloads else 0.0

    stats = {
        "tests": len(rows),
        "start": start,
        "end": end,
        "avgDown": round(average(downloads) or 0.0, 1),
        "medianDown": round(_quantile(downloads, 0.5) or 0.0, 1),
        "avgUp": round(average(uploads) or 0.0, 1),
        "avgPing": round(average(pings) or 0.0, 2),
        "p05": round(p05 or 0.0, 1),
        "p95": round(p95 or 0.0, 1),
        "pct250": round(pct250, 1),
        "pct300": round(pct300, 1),
    }
    return data, stats


def generate_interactive_dashboard(history: dict[str, list[dict[str, Any]]], now: datetime, output_path: str) -> tuple[bool, str]:
    rows = _merge_history(history, now, days=30)
    if not rows:
        return False, "No speed data available for interactive dashboard"

    data, stats = _build_dashboard_payload(rows)
    payload = _render_interactive_dashboard_html(data, stats)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")
    return True, f"Interactive dashboard written to {output}"


def _render_interactive_dashboard_html(data: list[dict[str, Any]], stats: dict[str, Any]) -> str:
    data_json = json.dumps(data)
    stats_json = json.dumps(stats)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pi Probe NBN Interactive Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
:root {{
  --bg: #070b14; --panel: rgba(17, 28, 47, .78); --panel2: rgba(15, 23, 42, .9);
  --border: rgba(148, 163, 184, .18); --text: #f8fafc; --muted: #94a3b8;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--text);
  background:
    radial-gradient(circle at top left, rgba(56,189,248,.18), transparent 32rem),
    radial-gradient(circle at top right, rgba(34,197,94,.13), transparent 30rem),
    linear-gradient(180deg, #020617, var(--bg));
  min-height: 100vh;
}}
.wrap {{ max-width: 1480px; margin: 0 auto; padding: 28px; }}
.hero {{ display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; margin-bottom: 20px; }}
h1 {{ margin: 0; font-size: clamp(28px, 4vw, 48px); letter-spacing: -0.05em; }}
.subtitle {{ color: var(--muted); margin-top: 8px; font-size: 15px; }}
.badge {{
  border: 1px solid var(--border); background: rgba(15,23,42,.7); padding: 10px 14px; border-radius: 999px;
  color: #dbeafe; white-space: nowrap; box-shadow: 0 20px 60px rgba(0,0,0,.25);
}}
.controls {{
  display: grid; grid-template-columns: 1.2fr 1fr 1fr 1fr; gap: 14px; padding: 14px;
  border: 1px solid var(--border); background: var(--panel2); border-radius: 22px; margin-bottom: 18px; backdrop-filter: blur(12px);
}}
label {{ display:block; color: var(--muted); font-size: 12px; font-weight: 700; margin-bottom: 7px; text-transform: uppercase; letter-spacing: .08em; }}
select, input {{
  width: 100%; border: 1px solid var(--border); background: rgba(2,6,23,.75); color: var(--text);
  border-radius: 13px; padding: 11px 12px; outline: none;
}}
.kpis {{ display:grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 18px; }}
.card {{
  position: relative; overflow: hidden; padding: 18px; min-height: 118px; border: 1px solid var(--border);
  background: var(--panel); border-radius: 24px; box-shadow: 0 24px 60px rgba(0,0,0,.22); backdrop-filter: blur(14px);
}}
.card:after {{
  content:""; position:absolute; inset:auto -30px -50px auto; width:130px; height:130px;
  background: radial-gradient(circle, rgba(56,189,248,.2), transparent 70%);
}}
.kpi-label {{ color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }}
.kpi-value {{ font-size: 32px; font-weight: 900; letter-spacing: -.05em; margin-top: 14px; }}
.kpi-sub {{ color: var(--muted); font-size: 12px; margin-top: 8px; }}
.grid {{ display:grid; grid-template-columns: 1.45fr .95fr; gap: 18px; }}
.panel {{
  border: 1px solid var(--border); background: var(--panel); border-radius: 26px; padding: 16px;
  box-shadow: 0 24px 70px rgba(0,0,0,.24); backdrop-filter: blur(14px);
}}
.panel h2 {{ margin: 0 0 4px; font-size: 18px; letter-spacing: -.03em; }}
.panel p {{ margin: 0 0 12px; color: var(--muted); font-size: 13px; }}
.chart {{ height: 380px; }}
.smallchart {{ height: 320px; }}
.wide {{ grid-column: 1 / -1; }}
.insights {{ display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 12px; }}
.insight {{ background: rgba(2,6,23,.45); border:1px solid var(--border); border-radius: 18px; padding: 14px; }}
.insight b {{ display:block; margin-bottom: 6px; }}
.insight span {{ color: var(--muted); font-size: 13px; }}
@media (max-width: 1050px) {{
  .controls, .kpis, .grid, .insights {{ grid-template-columns: 1fr; }}
  .hero {{ align-items: flex-start; flex-direction: column; }}
  .chart, .smallchart {{ height: 340px; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>Pi Probe NBN Dashboard</h1>
      <div class="subtitle" id="subtitle"></div>
    </div>
    <div class="badge" id="badge"></div>
  </div>

  <div class="controls">
    <div><label>Metric</label><select id="metric"><option value="download">Download Mbps</option><option value="upload">Upload Mbps</option><option value="ping">Ping ms</option></select></div>
    <div><label>Minimum speed threshold</label><input id="threshold" type="number" value="250" min="0" step="10"></div>
    <div><label>Day filter</label><select id="dayFilter"><option value="all">All days</option><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option><option>Saturday</option><option>Sunday</option></select></div>
    <div><label>Chart theme</label><select id="theme"><option value="premium">Premium dark</option><option value="clean">Clean light</option></select></div>
  </div>

  <div class="kpis">
    <div class="card"><div class="kpi-label">Median download</div><div class="kpi-value" id="kpiMedian"></div><div class="kpi-sub">Typical observed speed</div></div>
    <div class="card"><div class="kpi-label">Average upload</div><div class="kpi-value" id="kpiUpload"></div><div class="kpi-sub">Upstream capacity</div></div>
    <div class="card"><div class="kpi-label">Average ping</div><div class="kpi-value" id="kpiPing"></div><div class="kpi-sub">Latency profile</div></div>
    <div class="card"><div class="kpi-label">Reliability floor</div><div class="kpi-value" id="kpiFloor"></div><div class="kpi-sub">5th percentile download</div></div>
    <div class="card"><div class="kpi-label">Above threshold</div><div class="kpi-value" id="kpiThreshold"></div><div class="kpi-sub" id="kpiThresholdSub"></div></div>
  </div>

  <div class="grid">
    <div class="panel"><h2>Performance timeline</h2><p>Hover for exact readings. Use metric selector to swap between download, upload and ping.</p><div id="timeline" class="chart"></div></div>
    <div class="panel"><h2>Distribution</h2><p>Shows how often your connection sits in each performance band.</p><div id="histogram" class="chart"></div></div>
    <div class="panel"><h2>Hour × weekday heatmap</h2><p>Spot recurring slow periods by local time.</p><div id="heatmap" class="smallchart"></div></div>
    <div class="panel"><h2>Latency relationship</h2><p>Each dot is a test: download speed versus ping.</p><div id="scatter" class="smallchart"></div></div>
    <div class="panel wide"><h2>Executive readout</h2><p>Automatically updates when filters change.</p>
      <div class="insights">
        <div class="insight"><b id="bestHour"></b><span>Highest average download window.</span></div>
        <div class="insight"><b id="slowHour"></b><span>Lowest average download window.</span></div>
        <div class="insight"><b id="peakSpeed"></b><span>Maximum measured download result.</span></div>
        <div class="insight"><b id="testCount"></b><span>Number of tests after filters.</span></div>
      </div>
    </div>
  </div>
</div>
<script>
const rawData = {data_json};
const stats = {stats_json};
let dark = true;
document.getElementById("subtitle").textContent = `Interactive history view · Adelaide local time · ${{stats.start}} – ${{stats.end}}`;
document.getElementById("badge").textContent = `Dataset: ${{stats.tests.toLocaleString()}} speed tests`;
function layoutBase() {{
  return {{
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: {{ color: dark ? "#dbeafe" : "#0f172a", family: "Inter, system-ui, sans-serif" }},
    margin: {{ l: 52, r: 22, t: 24, b: 52 }},
    xaxis: {{ gridcolor: dark ? "rgba(148,163,184,.12)" : "rgba(15,23,42,.12)", zerolinecolor: "rgba(148,163,184,.16)" }},
    yaxis: {{ gridcolor: dark ? "rgba(148,163,184,.12)" : "rgba(15,23,42,.12)", zerolinecolor: "rgba(148,163,184,.16)" }},
    hoverlabel: {{ bgcolor: dark ? "#0f172a" : "#ffffff", bordercolor: "#38bdf8", font: {{ color: dark ? "#f8fafc" : "#0f172a" }} }}
  }};
}}
function quantile(arr, q) {{
  const v = arr.filter(x => x !== null && !Number.isNaN(x)).sort((a,b)=>a-b);
  if (!v.length) return null;
  const pos = (v.length - 1) * q, base = Math.floor(pos), rest = pos - base;
  return v[base + 1] !== undefined ? v[base] + rest * (v[base+1]-v[base]) : v[base];
}}
function avg(arr) {{
  const v = arr.filter(x => x !== null && !Number.isNaN(x));
  return v.length ? v.reduce((a,b)=>a+b,0) / v.length : 0;
}}
function filteredData() {{
  const day = document.getElementById("dayFilter").value;
  return rawData.filter(d => day === "all" || d.day === day);
}}
function update() {{
  const metric = document.getElementById("metric").value;
  const threshold = Number(document.getElementById("threshold").value || 0);
  const data = filteredData();
  const suffix = metric === "ping" ? " ms" : " Mbps";
  const values = data.map(d => d[metric]).filter(v => v !== null);
  const downloads = data.map(d => d.download).filter(v => v !== null);
  document.getElementById("kpiMedian").textContent = (quantile(downloads, .5) || 0).toFixed(1) + " Mbps";
  document.getElementById("kpiUpload").textContent = avg(data.map(d => d.upload)).toFixed(1) + " Mbps";
  document.getElementById("kpiPing").textContent = avg(data.map(d => d.ping)).toFixed(2) + " ms";
  document.getElementById("kpiFloor").textContent = (quantile(downloads, .05) || 0).toFixed(1) + " Mbps";
  const pct = downloads.length ? downloads.filter(v => v >= threshold).length / downloads.length * 100 : 0;
  document.getElementById("kpiThreshold").textContent = pct.toFixed(1) + "%";
  document.getElementById("kpiThresholdSub").textContent = `Tests ≥${{threshold}} Mbps`;
  const hourly = Array.from({{length:24}}, (_,h) => {{
    const vals = data.filter(d => d.hour === h).map(d => d.download).filter(v=>v!==null);
    return {{ hour:h, value: avg(vals), n: vals.length }};
  }}).filter(d => d.n > 0);
  const best = hourly.length ? hourly.reduce((a,b)=> b.value > a.value ? b : a, hourly[0]) : null;
  const slow = hourly.length ? hourly.reduce((a,b)=> b.value < a.value ? b : a, hourly[0]) : null;
  document.getElementById("bestHour").textContent = best ? `Best hour: ${{String(best.hour).padStart(2,"0")}}:00 · ${{best.value.toFixed(0)}} Mbps` : "Best hour: n/a";
  document.getElementById("slowHour").textContent = slow ? `Slowest hour: ${{String(slow.hour).padStart(2,"0")}}:00 · ${{slow.value.toFixed(0)}} Mbps` : "Slowest hour: n/a";
  document.getElementById("peakSpeed").textContent = downloads.length ? `Peak speed: ${{Math.max(...downloads).toFixed(1)}} Mbps` : "Peak speed: n/a";
  document.getElementById("testCount").textContent = `Tests shown: ${{data.length.toLocaleString()}}`;
  const lineLayout = layoutBase();
  lineLayout.yaxis.title = metric === "ping" ? "Milliseconds" : "Mbps";
  Plotly.newPlot("timeline", [{{
    x: data.map(d=>d.datetime), y: data.map(d=>d[metric]), text: data.map(d=>d.label), type: "scatter", mode: "lines+markers",
    line: {{ width: 2.5, shape: "spline", color: "#38bdf8" }}, marker: {{ size: 5, color: "#7dd3fc" }},
    hovertemplate: "%{{text}}<br>" + metric + ": %{{y:.2f}}" + suffix + "<extra></extra>"
  }}], lineLayout, {{ responsive: true, displaylogo: false }});
  const histLayout = layoutBase();
  histLayout.xaxis.title = metric === "ping" ? "Milliseconds" : "Mbps";
  histLayout.yaxis.title = "Tests";
  Plotly.newPlot("histogram", [{{
    x: values, type: "histogram", nbinsx: 28, marker: {{ color: "#38bdf8", opacity: .82 }},
    hovertemplate: "Value band: %{{x}}<br>Tests: %{{y}}<extra></extra>"
  }}], histLayout, {{ responsive: true, displaylogo: false }});
  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  const z = days.map(day => Array.from({{length:24}}, (_,h) => {{
    const vals = data.filter(d => d.day === day && d.hour === h).map(d => d.download).filter(v=>v!==null);
    return vals.length ? avg(vals) : null;
  }}));
  const heatLayout = layoutBase();
  heatLayout.xaxis.title = "Hour";
  Plotly.newPlot("heatmap", [{{
    z, x: Array.from({{length:24}}, (_,i)=>i), y: days.map(d=>d.slice(0,3)), type: "heatmap",
    colorscale: "Turbo", colorbar: {{ title: "Mbps" }},
    hovertemplate: "%{{y}} %{{x}}:00<br>Avg download: %{{z:.1f}} Mbps<extra></extra>"
  }}], heatLayout, {{ responsive: true, displaylogo: false }});
  const scatterLayout = layoutBase();
  scatterLayout.xaxis.title = "Download Mbps";
  scatterLayout.yaxis.title = "Ping ms";
  Plotly.newPlot("scatter", [{{
    x: data.map(d=>d.download), y: data.map(d=>d.ping), text: data.map(d=>d.label), type: "scatter", mode: "markers",
    marker: {{ size: 8, opacity: .72, color: "#22c55e" }},
    hovertemplate: "%{{text}}<br>Download: %{{x:.2f}} Mbps<br>Ping: %{{y:.2f}} ms<extra></extra>"
  }}], scatterLayout, {{ responsive: true, displaylogo: false }});
}}
document.getElementById("metric").addEventListener("change", update);
document.getElementById("threshold").addEventListener("input", update);
document.getElementById("dayFilter").addEventListener("change", update);
document.getElementById("theme").addEventListener("change", (e) => {{
  dark = e.target.value === "premium";
  document.body.style.background = dark
    ? "radial-gradient(circle at top left, rgba(56,189,248,.18), transparent 32rem), radial-gradient(circle at top right, rgba(34,197,94,.13), transparent 30rem), linear-gradient(180deg, #020617, #070b14)"
    : "linear-gradient(180deg, #f8fafc, #e2e8f0)";
  document.body.style.color = dark ? "#f8fafc" : "#0f172a";
  update();
}});
update();
</script>
</body>
</html>
"""


def generate_premium_dashboard(history: dict[str, list[dict[str, Any]]], now: datetime, chart_path: str, speed_result: SpeedResult) -> tuple[bool, str]:
    if plt is None or mdates is None:
        return False, "matplotlib not installed"

    rows = _merge_history(history, now, days=30)
    if not rows:
        return False, "No speed data available for premium dashboard"

    data, stats = _build_dashboard_payload(rows)
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

    score = _score_connection(stats["avgDown"], stats["avgUp"], stats["avgPing"], stats["pct250"])
    cards = [
        ("Typical download", f"{stats['medianDown']:.0f} Mbps", f"Average {stats['avgDown']:.0f} Mbps"),
        ("Upload average", f"{stats['avgUp']:.1f} Mbps", "Typical upstream"),
        ("Average ping", f"{stats['avgPing']:.1f} ms", "Typical latency"),
        ("Reliability", f"{score}/100", f"{stats['pct250']:.0f}% of tests ≥250 Mbps"),
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
    for row in rows:
        if row.download is None:
            continue
        by_day.setdefault(row.timestamp.strftime("%Y-%m-%d"), []).append(row.download)
    day_dates = [datetime.fromisoformat(day) for day in sorted(by_day)]
    day_median = [_quantile(by_day[day.strftime("%Y-%m-%d")], 0.5) or 0.0 for day in day_dates]
    day_average = [average(by_day[day.strftime("%Y-%m-%d")]) or 0.0 for day in day_dates]
    day_low = [min(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]
    day_high = [max(by_day[day.strftime("%Y-%m-%d")]) for day in day_dates]

    ax_band_panel = figure.add_subplot(gs[1, :7])
    ax_band = style_panel(ax_band_panel, "Daily Download Reliability Band")
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
                row.download for row in rows
                if row.download is not None and row.timestamp.strftime("%A") == day_name and row.timestamp.hour == hour
            ]
            heat_values[dow_idx][hour] = average(hour_values)
    ax_heat_panel = figure.add_subplot(gs[1, 7:])
    ax_heat = style_panel(ax_heat_panel, "Speed Heatmap by Hour and Weekday", "Average speed by local hour.")
    image = ax_heat.imshow(heat_values, aspect="auto", cmap="viridis")
    ax_heat.set_yticks(range(7), [name[:3] for name in DAY_NAMES], color="#cbd5e1")
    ax_heat.set_xticks(range(0, 24, 3))
    ax_heat.set_xticklabels([str(hour) for hour in range(0, 24, 3)], color="#cbd5e1")
    cbar = figure.colorbar(image, ax=ax_heat, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(colors="#cbd5e1")

    hourly_values: list[list[float]] = [[] for _ in range(24)]
    for row in rows:
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
    ax_times = style_panel(ax_times_panel, "Best and Slowest Times of Day")
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
    best_hour = max(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)
    slow_hour = min(((hour, value) for hour, value in enumerate(hour_avg) if value is not None), key=lambda item: item[1], default=None)
    lines = [
        f"• Typical result: {stats['medianDown']:.0f} Mbps down",
        f"• Reliability floor: {stats['p05']:.0f} Mbps",
        f"• Peak band: {stats['p95']:.0f} Mbps",
        f"• Best hour: {best_hour[0]:02d}:00" if best_hour else "• Best hour: n/a",
        f"• Slowest hour: {slow_hour[0]:02d}:00" if slow_hour else "• Slowest hour: n/a",
        f"• Average ping: {stats['avgPing']:.1f} ms",
    ]
    for idx, line in enumerate(lines):
        ax_exec.text(0.06, 0.80 - idx * 0.10, line, transform=ax_exec.transAxes, color="#cbd5e1", fontsize=12.2, ha="left")

    figure.text(
        0.04,
        0.025,
        "Shaded bands show normal variation. Heatmap shows recurring time-of-day patterns.",
        color="#94a3b8",
        fontsize=10,
        ha="left",
    )

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Premium dashboard generated"


def serve_interactive_dashboard(output_path: str, host: str, port: int) -> int:
    file_path = Path(output_path).resolve()
    directory = file_path.parent

    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(directory), **kwargs)

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Serving interactive dashboard at http://{host}:{port}/{file_path.name}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
