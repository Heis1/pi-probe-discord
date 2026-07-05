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
except ImportError:
    plt = None


def _classify_source(source: str) -> str:
    try:
        ip = ipaddress.ip_address(source)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "LAN"
    if ip.is_multicast:
        return "multicast"
    return "external"


def _wrap(value: str, width: int) -> str:
    return "\n".join(textwrap.wrap(value, width=width, break_long_words=False)) or value


def generate_firewall_chart(snapshot: FirewallSnapshot, chart_path: str) -> tuple[bool, str]:
    if plt is None:
        return False, "matplotlib not installed"

    figure = plt.figure(figsize=(14.5, 7.4), facecolor="#09111f")
    gs = figure.add_gridspec(3, 12, height_ratios=[0.34, 1.25, 3.25], hspace=0.30, wspace=0.28)

    def style_panel(ax: Any, facecolor: str = "#0f1a2e") -> None:
        ax.set_facecolor(facecolor)
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)

    def axis_panel(ax: Any, title: str, subtitle: str) -> Any:
        style_panel(ax)
        ax.text(0.04, 0.94, title, transform=ax.transAxes, color="#f8fafc", fontsize=17, fontweight="bold", ha="left", va="top")
        ax.text(0.04, 0.84, subtitle, transform=ax.transAxes, color="#8fa3ba", fontsize=10, ha="left", va="top")
        inner = ax.inset_axes([0.08, 0.13, 0.86, 0.62])
        inner.set_facecolor("#0f1a2e")
        inner.grid(color="#2a3951", linewidth=0.7, alpha=0.55, axis="x")
        inner.tick_params(colors="#9fb0c7", labelsize=10)
        for spine in inner.spines.values():
            spine.set_color("#2a3951")
        return inner

    def metric(ax: Any, x: float, label: str, value: str, detail: str, color: str) -> None:
        ax.text(x, 0.72, label, transform=ax.transAxes, color="#8fa3ba", fontsize=10.5, ha="left")
        ax.text(x, 0.40, value, transform=ax.transAxes, color=color, fontsize=26, fontweight="bold", ha="left")
        ax.text(x, 0.16, detail, transform=ax.transAxes, color="#9fb0c7", fontsize=9.5, ha="left")

    if snapshot.ssh_attempts > 0:
        verdict = "SSH PROBING DETECTED"
        verdict_color = "#f97316"
        verdict_detail = "Inbound SSH attempts appeared in this window."
    elif len(snapshot.noisy_sources) >= 3 or snapshot.blocked_entries >= 1000:
        verdict = "NOISY BUT CONTAINED"
        verdict_color = "#fbbf24"
        verdict_detail = "Repeated blocks are concentrated around a small source set."
    else:
        verdict = "NORMAL BLOCKING"
        verdict_color = "#5eead4"
        verdict_detail = "Recent firewall activity looks like routine background traffic."

    ax_title = figure.add_subplot(gs[0, :])
    style_panel(ax_title, facecolor="#09111f")
    ax_title.text(0.00, 0.92, "Firewall Snapshot", color="#f8fafc", fontsize=22, fontweight="bold", ha="left", va="top")
    ax_title.text(0.00, 0.20, f"Window {snapshot.window_hours}h | source {snapshot.log_source}", color="#8fa3ba", fontsize=10.5, ha="left", va="top")

    ax_header = figure.add_subplot(gs[1, :5])
    style_panel(ax_header)
    ax_header.text(0.04, 0.70, verdict, transform=ax_header.transAxes, color=verdict_color, fontsize=24, fontweight="bold", ha="left")
    ax_header.text(0.04, 0.38, verdict_detail, transform=ax_header.transAxes, color="#cbd5e1", fontsize=10.8, ha="left", va="top")
    ax_header.text(
        0.04,
        0.13,
        f"Policy {snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out | Logging {snapshot.status.logging}",
        transform=ax_header.transAxes,
        color="#9fb0c7",
        fontsize=10,
        ha="left",
    )

    ax_metrics = figure.add_subplot(gs[1, 5:])
    style_panel(ax_metrics)
    metric(ax_metrics, 0.05, "Blocked", str(snapshot.blocked_entries), "UFW BLOCK entries", "#f8fafc")
    metric(ax_metrics, 0.36, "Noisy sources", str(len(snapshot.noisy_sources)), "over threshold", "#fbbf24")
    metric(ax_metrics, 0.68, "SSH attempts", str(snapshot.ssh_attempts), "DPT=22 hits", "#fb923c")

    top_sources = snapshot.top_sources[:5] or [("none", 0)]
    ax_sources_panel = figure.add_subplot(gs[2, :6])
    ax_sources = axis_panel(ax_sources_panel, "Top Sources", "Most active sources, tagged by address type.")
    source_labels = [
        f"{source} ({_classify_source(source)})" if source != "none" else "none"
        for source, _count in reversed(top_sources)
    ]
    source_values = [count for _source, count in reversed(top_sources)]
    source_pos = list(range(len(source_labels)))
    source_colors = [
        "#38bdf8" if "(LAN)" in label or "(link-local)" in label else "#f97316" if "(external)" in label else "#94a3b8"
        for label in source_labels
    ]
    ax_sources.barh(source_pos, source_values, color=source_colors)
    ax_sources.set_yticks(source_pos, source_labels)

    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    ax_ports_panel = figure.add_subplot(gs[2, 6:9])
    ax_ports = axis_panel(ax_ports_panel, "Top Ports", "Blocked destination ports.")
    port_labels = [port for port, _count in reversed(top_ports)]
    port_values = [count for _port, count in reversed(top_ports)]
    port_pos = list(range(len(port_labels)))
    ax_ports.barh(port_pos, port_values, color="#fb923c")
    ax_ports.set_yticks(port_pos, port_labels)

    ax_readout = figure.add_subplot(gs[2, 9:])
    style_panel(ax_readout)
    ax_readout.text(0.06, 0.92, "Readout", transform=ax_readout.transAxes, color="#f8fafc", fontsize=17, fontweight="bold", ha="left", va="top")
    top_source = snapshot.top_sources[0] if snapshot.top_sources else ("none", 0)
    top_port = snapshot.top_ports[0] if snapshot.top_ports else ("none", 0)
    top_source_text = f"{top_source[0]} ({top_source[1]}, {_classify_source(top_source[0])})" if top_source[0] != "none" else "none"
    top_port_text = f"{top_port[0]} ({top_port[1]})" if top_port[0] != "none" else "none"
    note = snapshot.notes[0] if snapshot.notes else "No unusual firewall notes."
    lines = [
        f"Why: {verdict.title()}",
        f"Top source: {top_source_text}",
        f"Top port: {top_port_text}",
        f"Protocol: {snapshot.top_protocols[0][0]} ({snapshot.top_protocols[0][1]})" if snapshot.top_protocols else "Protocol: n/a",
        f"Interfaces: {', '.join(f'{k}:{v}' for k, v in snapshot.top_inbound_interfaces[:2]) or 'none'}",
        f"Note: {note}",
    ]
    y = 0.76
    for line in lines:
        wrapped = _wrap(line, 33)
        ax_readout.text(0.06, y, wrapped, transform=ax_readout.transAxes, color="#cbd5e1", fontsize=10.2, ha="left", va="top")
        y -= 0.095 * (wrapped.count("\n") + 1)

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
