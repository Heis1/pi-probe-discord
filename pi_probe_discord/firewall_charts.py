from __future__ import annotations

import ipaddress
import textwrap
from pathlib import Path
from typing import Any

from .firewall import FirewallSnapshot

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle
except ImportError:
    plt = None
    Rectangle = None


BG = "#08111f"
PANEL = "#111c30"
TEXT = "#f8fafc"
MUTED = "#9fb0c7"
FAINT = "#64748b"
WARN = "#fbbf24"
ORANGE = "#fb923c"
BLUE = "#38bdf8"


def _classify_source(source: str) -> str:
    try:
        ip = ipaddress.ip_address(source)
    except ValueError:
        return "unknown"
    if ip.is_private:
        return "LAN"
    if ip.is_link_local:
        return "link-local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    return "external"


def _wrap(value: str, width: int) -> str:
    return "\n".join(textwrap.wrap(value, width=width, break_long_words=False)) or value


def _panel(ax: Any) -> None:
    ax.set_facecolor(PANEL)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)


def _metric(ax: Any, x: float, label: str, value: str, detail: str, color: str = TEXT) -> None:
    ax.text(x, 0.78, label, color=MUTED, fontsize=10.5, ha="left", va="top")
    ax.text(x, 0.48, value, color=color, fontsize=26, fontweight="bold", ha="left", va="center")
    ax.text(x, 0.20, detail, color=MUTED, fontsize=9.5, ha="left", va="top")


def _table_row(ax: Any, y: float, rank: int, label: str, value: int, max_value: int, color: str) -> None:
    ax.text(0.05, y, str(rank), color=FAINT, fontsize=12, fontweight="bold", ha="left", va="center")
    ax.text(0.12, y, label, color=TEXT, fontsize=13, ha="left", va="center")
    ax.text(0.92, y, str(value), color=TEXT, fontsize=13, ha="right", va="center")
    bar_width = 0.76 * (value / max(max_value, 1))
    ax.add_patch(Rectangle((0.12, y - 0.055), bar_width, 0.018, color=color, linewidth=0))


def generate_firewall_chart(snapshot: FirewallSnapshot, chart_path: str) -> tuple[bool, str]:
    if plt is None or Rectangle is None:
        return False, "matplotlib not installed"

    if snapshot.ssh_attempts > 0:
        verdict = "SSH probing detected"
        verdict_color = ORANGE
        verdict_detail = "Blocks include destination port 22 attempts."
    elif len(snapshot.noisy_sources) >= 3 or snapshot.blocked_entries >= 1000:
        verdict = "Noisy but contained"
        verdict_color = WARN
        verdict_detail = "Blocks are concentrated around a small set of sources."
    else:
        verdict = "Normal blocking"
        verdict_color = "#5eead4"
        verdict_detail = "Activity looks like routine background traffic."

    figure = plt.figure(figsize=(13.6, 7.65), facecolor=BG)

    ax_title = figure.add_axes([0.04, 0.88, 0.92, 0.10])
    _panel(ax_title)
    ax_title.set_facecolor(BG)
    ax_title.text(0.00, 0.76, "Firewall Snapshot", color=TEXT, fontsize=22, fontweight="bold", ha="left", va="center")
    ax_title.text(0.00, 0.20, f"Window {snapshot.window_hours}h | source {snapshot.log_source}", color=MUTED, fontsize=10.5, ha="left", va="center")

    ax_status = figure.add_axes([0.04, 0.72, 0.92, 0.13])
    _panel(ax_status)
    ax_status.text(0.035, 0.58, verdict.upper(), color=verdict_color, fontsize=20, fontweight="bold", ha="left", va="center")
    ax_status.text(0.035, 0.25, verdict_detail, color=TEXT, fontsize=10.8, ha="left", va="center")
    _metric(ax_status, 0.42, "Blocked", str(snapshot.blocked_entries), "UFW BLOCK entries")
    _metric(ax_status, 0.62, "Noisy sources", str(len(snapshot.noisy_sources)), "over threshold", WARN)
    _metric(ax_status, 0.82, "SSH attempts", str(snapshot.ssh_attempts), "DPT=22 hits", ORANGE)

    ax_sources = figure.add_axes([0.04, 0.29, 0.55, 0.39])
    _panel(ax_sources)
    ax_sources.text(0.05, 0.90, "Top Sources", color=TEXT, fontsize=19, fontweight="bold", ha="left", va="center")
    ax_sources.text(0.05, 0.80, "Sender IPs generating the most blocked events", color=MUTED, fontsize=10.5, ha="left", va="center")
    top_sources = snapshot.top_sources[:5] or [("none", 0)]
    source_max = max(count for _source, count in top_sources)
    y = 0.65
    for idx, (source, count) in enumerate(top_sources, start=1):
        label = f"{source} ({_classify_source(source)})" if source != "none" else "none"
        _table_row(ax_sources, y, idx, label, count, source_max, BLUE)
        y -= 0.12

    ax_ports = figure.add_axes([0.62, 0.29, 0.34, 0.39])
    _panel(ax_ports)
    ax_ports.text(0.06, 0.90, "Top Ports", color=TEXT, fontsize=19, fontweight="bold", ha="left", va="center")
    ax_ports.text(0.06, 0.80, "Blocked destinations", color=MUTED, fontsize=10.5, ha="left", va="center")
    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    port_max = max(count for _port, count in top_ports)
    y = 0.65
    for idx, (port, count) in enumerate(top_ports, start=1):
        _table_row(ax_ports, y, idx, port, count, port_max, ORANGE)
        y -= 0.12

    ax_summary = figure.add_axes([0.04, 0.08, 0.92, 0.17])
    _panel(ax_summary)
    top_source = snapshot.top_sources[0] if snapshot.top_sources else ("none", 0)
    top_port = snapshot.top_ports[0] if snapshot.top_ports else ("none", 0)
    protocol = f"{snapshot.top_protocols[0][0]} ({snapshot.top_protocols[0][1]})" if snapshot.top_protocols else "n/a"
    interfaces = ", ".join(f"{name}:{count}" for name, count in snapshot.top_inbound_interfaces[:2]) or "none"
    note = snapshot.notes[0] if snapshot.notes else "No unusual firewall notes."
    summary = (
        f"Policy {snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out. "
        f"Top source {top_source[0]} ({top_source[1]}, {_classify_source(top_source[0])}). "
        f"Top port {top_port[0]} ({top_port[1]}). "
        f"Protocol {protocol}. Interfaces {interfaces}. "
        f"IPv4/IPv6 {snapshot.ipv4_events}/{snapshot.ipv6_events}. Note: {note}"
    )
    ax_summary.text(0.035, 0.70, "Summary", color=TEXT, fontsize=15, fontweight="bold", ha="left", va="center")
    ax_summary.text(0.035, 0.36, _wrap(summary, 150), color=MUTED, fontsize=10.7, ha="left", va="center")

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
