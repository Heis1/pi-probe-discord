from __future__ import annotations

import ipaddress
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
        return "LAN/private"
    if ip.is_multicast:
        return "multicast"
    return "external"


def generate_firewall_chart(snapshot: FirewallSnapshot, chart_path: str) -> tuple[bool, str]:
    if plt is None:
        return False, "matplotlib not installed"

    figure = plt.figure(figsize=(14.5, 8.8), facecolor="#09111f")
    gs = figure.add_gridspec(4, 12, height_ratios=[0.34, 1.15, 2.25, 1.55], hspace=0.34, wspace=0.34)

    def style_panel(ax: Any, facecolor: str = "#0f1a2e") -> None:
        ax.set_facecolor(facecolor)
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)

    def style_axis_panel(ax: Any, title: str, subtitle: str | None = None) -> Any:
        style_panel(ax)
        ax.text(0.04, 0.94, title, transform=ax.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left", va="top")
        if subtitle:
            ax.text(0.04, 0.86, subtitle, transform=ax.transAxes, color="#72849b", fontsize=9.5, ha="left", va="top")
        inner = ax.inset_axes([0.06, 0.12, 0.88, 0.68])
        inner.set_facecolor("#0f1a2e")
        inner.grid(color="#223044", linewidth=0.7, alpha=0.5, axis="x")
        inner.tick_params(colors="#97a9bf", labelsize=9)
        for spine in inner.spines.values():
            spine.set_color("#233149")
        return inner

    def draw_metric(ax: Any, x_pos: float, label: str, value: str, detail: str, color: str) -> None:
        ax.text(x_pos, 0.72, label, transform=ax.transAxes, color="#8fa3ba", fontsize=10.5, ha="left")
        ax.text(x_pos, 0.41, value, transform=ax.transAxes, color=color, fontsize=25, fontweight="bold", ha="left")
        ax.text(x_pos, 0.17, detail, transform=ax.transAxes, color="#97a9bf", fontsize=9.5, ha="left")

    if snapshot.ssh_attempts > 0:
        verdict = "SSH PROBING DETECTED"
        verdict_color = "#f97316"
        verdict_detail = "Inbound SSH attempts were observed in the current firewall window."
    elif len(snapshot.noisy_sources) >= 3 or snapshot.blocked_entries >= 1000:
        verdict = "NOISY BUT CONTAINED"
        verdict_color = "#fbbf24"
        verdict_detail = "The firewall is actively dropping repeated traffic from a small set of sources."
    else:
        verdict = "NORMAL BLOCKING"
        verdict_color = "#5eead4"
        verdict_detail = "Recent firewall activity is consistent with routine background internet noise."

    ax_title = figure.add_subplot(gs[0, :])
    style_panel(ax_title, facecolor="#09111f")
    ax_title.text(0.00, 0.88, "Firewall Snapshot", color="#f8fafc", fontsize=20, fontweight="bold", ha="left", va="top")
    ax_title.text(
        0.00,
        0.24,
        f"Window {snapshot.window_hours}h | source {snapshot.log_source}",
        color="#72849b",
        fontsize=10.5,
        ha="left",
        va="top",
    )

    ax_header = figure.add_subplot(gs[1, :5])
    style_panel(ax_header)
    ax_header.axhline(0.0, color="#233149", linewidth=1.2)
    ax_header.text(0.04, 0.70, verdict, transform=ax_header.transAxes, color=verdict_color, fontsize=23, fontweight="bold", ha="left")
    ax_header.text(0.04, 0.36, verdict_detail, transform=ax_header.transAxes, color="#97a9bf", fontsize=11.5, ha="left", wrap=True)
    ax_header.text(
        0.04,
        0.13,
        f"Policy {snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out | Logging {snapshot.status.logging}",
        transform=ax_header.transAxes,
        color="#97a9bf",
        fontsize=10.5,
        ha="left",
    )

    ax_metrics = figure.add_subplot(gs[1, 5:])
    style_panel(ax_metrics)
    draw_metric(ax_metrics, 0.05, "Blocked", str(snapshot.blocked_entries), "UFW BLOCK entries", "#f8fafc")
    draw_metric(ax_metrics, 0.35, "Noisy sources", str(len(snapshot.noisy_sources)), "over threshold", "#fbbf24")
    draw_metric(ax_metrics, 0.67, "SSH attempts", str(snapshot.ssh_attempts), "DPT=22 hits", "#fb923c")

    top_sources = snapshot.top_sources[:5] or [("none", 0)]
    ax_sources_panel = figure.add_subplot(gs[2, :5])
    ax_sources = style_axis_panel(ax_sources_panel, "Top Sources", "Most active senders, classified by address type.")
    source_labels = [
        f"{source} ({_classify_source(source)})" if source != "none" else "none"
        for source, _count in reversed(top_sources)
    ]
    source_values = [count for _source, count in reversed(top_sources)]
    source_pos = list(range(len(source_labels)))
    source_colors = [
        "#38bdf8" if "LAN/private" in label or "link-local" in label else "#f97316" if "external" in label else "#94a3b8"
        for label in source_labels
    ]
    ax_sources.barh(source_pos, source_values, color=source_colors)
    ax_sources.set_yticks(source_pos, source_labels)

    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    ax_ports_panel = figure.add_subplot(gs[2, 5:8])
    ax_ports = style_axis_panel(ax_ports_panel, "Top Ports", "Destination ports or services most often blocked.")
    port_labels = [port for port, _count in reversed(top_ports)]
    port_values = [count for _port, count in reversed(top_ports)]
    port_pos = list(range(len(port_labels)))
    ax_ports.barh(port_pos, port_values, color="#fb923c")
    ax_ports.set_yticks(port_pos, port_labels)

    ax_exec = figure.add_subplot(gs[2, 8:])
    style_panel(ax_exec)
    ax_exec.text(0.05, 0.90, "Executive readout", transform=ax_exec.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left")
    top_source = snapshot.top_sources[0] if snapshot.top_sources else ("none", 0)
    top_port = snapshot.top_ports[0] if snapshot.top_ports else ("none", 0)
    top_source_text = f"{top_source[0]} ({top_source[1]}, {_classify_source(top_source[0])})" if top_source[0] != "none" else "none"
    top_port_text = f"{top_port[0]} ({top_port[1]})" if top_port[0] != "none" else "none"
    primary_note = snapshot.notes[0] if snapshot.notes else "No unusual firewall notes."
    summary_lines = [
        f"- Why flagged: {verdict.title()}",
        f"- Top source: {top_source_text}",
        f"- Top port: {top_port_text}",
        f"- DNS hits: {snapshot.dns_attempts} | IPv4/IPv6: {snapshot.ipv4_events}/{snapshot.ipv6_events}",
        f"- Main note: {primary_note}",
    ]
    for idx, line in enumerate(summary_lines):
        ax_exec.text(0.06, 0.74 - idx * 0.13, line, transform=ax_exec.transAxes, color="#cbd5e1", fontsize=10.8, ha="left", wrap=True)

    proto_data = snapshot.top_protocols[:4] or [("none", 0)]
    ax_proto_panel = figure.add_subplot(gs[3, :4])
    ax_proto = style_axis_panel(ax_proto_panel, "Protocol Mix", "Traffic mix in recent firewall events.")
    proto_labels = [proto for proto, _count in reversed(proto_data)]
    proto_values = [count for _proto, count in reversed(proto_data)]
    proto_pos = list(range(len(proto_labels)))
    ax_proto.barh(proto_pos, proto_values, color="#7dd3fc")
    ax_proto.set_yticks(proto_pos, proto_labels)

    iface_data = snapshot.top_inbound_interfaces[:4] or [("none", 0)]
    ax_ifaces_panel = figure.add_subplot(gs[3, 4:8])
    ax_ifaces = style_axis_panel(ax_ifaces_panel, "Inbound Interfaces", "Where blocked traffic arrived.")
    iface_labels = [iface for iface, _count in reversed(iface_data)]
    iface_values = [count for _iface, count in reversed(iface_data)]
    iface_pos = list(range(len(iface_labels)))
    ax_ifaces.barh(iface_pos, iface_values, color="#60a5fa")
    ax_ifaces.set_yticks(iface_pos, iface_labels)

    ax_notes = figure.add_subplot(gs[3, 8:])
    style_panel(ax_notes)
    ax_notes.text(0.05, 0.88, "Operating context", transform=ax_notes.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left")
    notes = [
        f"Allow rules: {snapshot.status.allow_rules}",
        f"Deny rules: {snapshot.status.deny_rules}",
        f"Allowed entries logged: {snapshot.allowed_entries}",
        f"Total entries reviewed: {snapshot.total_entries}",
        f"Log source: {snapshot.log_source}",
    ]
    if snapshot.log_error:
        notes.append(f"Log warning: {snapshot.log_error}")
    for idx, line in enumerate(notes[:6]):
        ax_notes.text(0.06, 0.72 - idx * 0.12, f"- {line}", transform=ax_notes.transAxes, color="#cbd5e1", fontsize=11.0, ha="left")

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
