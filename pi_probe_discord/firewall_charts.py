from __future__ import annotations

from pathlib import Path
from typing import Any

from .firewall import FirewallSnapshot

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    plt = None


def generate_firewall_chart(snapshot: FirewallSnapshot, chart_path: str) -> tuple[bool, str]:
    if plt is None:
        return False, "matplotlib not installed"

    figure = plt.figure(figsize=(13.8, 8.4), facecolor="#111827")
    gs = figure.add_gridspec(2, 3, height_ratios=[1.0, 2.0], hspace=0.42, wspace=0.34)

    figure.text(0.04, 0.95, "Firewall Snapshot", color="#f8fafc", fontsize=24, fontweight="bold", ha="left", va="top")
    figure.text(
        0.04,
        0.915,
        f"Window {snapshot.window_hours}h · source {snapshot.log_source}",
        color="#94a3b8",
        fontsize=12,
        ha="left",
        va="top",
    )

    cards = [
        ("Blocked entries", str(snapshot.blocked_entries), "Recent blocked packets"),
        ("Noisy sources", str(len(snapshot.noisy_sources)), "Repeated inbound senders"),
        ("SSH attempts", str(snapshot.ssh_attempts), "Destination port 22"),
    ]
    for idx, (title, value, subtitle) in enumerate(cards):
        ax = figure.add_subplot(gs[0, idx])
        ax.set_facecolor("#152033")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.text(0.05, 0.68, title, transform=ax.transAxes, color="#cbd5e1", fontsize=12, fontweight="bold", ha="left")
        ax.text(0.05, 0.34, value, transform=ax.transAxes, color="#f8fafc", fontsize=30, fontweight="bold", ha="left")
        ax.text(0.05, 0.13, subtitle, transform=ax.transAxes, color="#94a3b8", fontsize=10.5, ha="left")

    def _style_axis(ax: Any, title: str) -> None:
        ax.set_facecolor("#152033")
        ax.set_title(title, loc="left", color="#f8fafc", fontsize=16, fontweight="bold", pad=12)
        ax.grid(color="#334155", linewidth=0.8, alpha=0.6, axis="x")
        ax.tick_params(colors="#cbd5e1", labelsize=10)
        for spine in ax.spines.values():
            spine.set_color("#334155")

    top_sources = snapshot.top_sources[:5] or [("none", 0)]
    ax_sources = figure.add_subplot(gs[1, 0])
    _style_axis(ax_sources, "Top sources")
    ax_sources.barh([item[0] for item in reversed(top_sources)], [item[1] for item in reversed(top_sources)], color="#38bdf8")

    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    ax_ports = figure.add_subplot(gs[1, 1])
    _style_axis(ax_ports, "Top ports")
    ax_ports.barh([item[0] for item in reversed(top_ports)], [item[1] for item in reversed(top_ports)], color="#f97316")

    ax_summary = figure.add_subplot(gs[1, 2])
    ax_summary.set_facecolor("#152033")
    ax_summary.set_xticks([])
    ax_summary.set_yticks([])
    for spine in ax_summary.spines.values():
        spine.set_visible(False)
    ax_summary.text(0.04, 0.93, "Executive readout", transform=ax_summary.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left")
    summary_lines = [
        f"• Policy: {snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out",
        f"• IPv4 events: {snapshot.ipv4_events}",
        f"• IPv6 events: {snapshot.ipv6_events}",
        f"• DNS attempts: {snapshot.dns_attempts}",
        f"• Top protocol: {snapshot.top_protocols[0][0]} ({snapshot.top_protocols[0][1]})" if snapshot.top_protocols else "• Top protocol: n/a",
        f"• Note: {snapshot.notes[0]}" if snapshot.notes else "• Note: no additional notes",
    ]
    for idx, line in enumerate(summary_lines):
        ax_summary.text(0.06, 0.80 - idx * 0.11, line, transform=ax_summary.transAxes, color="#cbd5e1", fontsize=11.5, ha="left")

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
