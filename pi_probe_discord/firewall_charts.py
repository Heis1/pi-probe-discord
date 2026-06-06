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

    figure = plt.figure(figsize=(14.5, 8.6), facecolor="#09111f")
    gs = figure.add_gridspec(3, 12, height_ratios=[1.0, 2.2, 1.5], hspace=0.34, wspace=0.34)

    def style_panel(ax: Any) -> None:
        ax.set_facecolor("#0f1a2e")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)

    def style_axis_panel(ax: Any, title: str, subtitle: str | None = None) -> Any:
        ax.set_facecolor("#0f1a2e")
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
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

    figure.text(0.04, 0.955, "Firewall Snapshot", color="#f8fafc", fontsize=20, fontweight="bold", ha="left", va="top")
    figure.text(0.04, 0.933, f"Window {snapshot.window_hours}h · source {snapshot.log_source}", color="#72849b", fontsize=10.5, ha="left", va="top")

    ax_header = figure.add_subplot(gs[0, :])
    style_panel(ax_header)
    ax_header.axhline(0.0, color="#233149", linewidth=1.2)
    ax_header.text(0.03, 0.72, verdict, transform=ax_header.transAxes, color=verdict_color, fontsize=24, fontweight="bold", ha="left")
    ax_header.text(0.03, 0.36, verdict_detail, transform=ax_header.transAxes, color="#97a9bf", fontsize=12, ha="left")

    metric_blocks = [
        (0.42, "Blocked", str(snapshot.blocked_entries)),
        (0.58, "Noisy sources", str(len(snapshot.noisy_sources))),
        (0.74, "SSH attempts", str(snapshot.ssh_attempts)),
    ]
    for x_pos, label, value in metric_blocks:
        ax_header.text(x_pos, 0.71, label, transform=ax_header.transAxes, color="#72849b", fontsize=10, ha="left")
        ax_header.text(x_pos, 0.47, value, transform=ax_header.transAxes, color="#f8fafc", fontsize=24, fontweight="bold", ha="left")
    ax_header.text(0.42, 0.18, f"Policy {snapshot.status.default_incoming} in / {snapshot.status.default_outgoing} out", transform=ax_header.transAxes, color="#97a9bf", fontsize=11, ha="left")
    ax_header.text(0.74, 0.18, f"Logging {snapshot.status.logging}", transform=ax_header.transAxes, color="#97a9bf", fontsize=11, ha="left")

    top_sources = snapshot.top_sources[:5] or [("none", 0)]
    ax_sources_panel = figure.add_subplot(gs[1, :5])
    ax_sources = style_axis_panel(ax_sources_panel, "Top Sources", "Most active senders in the current window.")
    source_labels = [item[0] for item in reversed(top_sources)]
    source_values = [item[1] for item in reversed(top_sources)]
    source_pos = list(range(len(source_labels)))
    ax_sources.barh(source_pos, source_values, color="#58b5ff")
    ax_sources.set_yticks(source_pos, source_labels)

    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    ax_ports_panel = figure.add_subplot(gs[1, 5:8])
    ax_ports = style_axis_panel(ax_ports_panel, "Top Ports", "Destination ports or services most often blocked.")
    port_labels = [item[0] for item in reversed(top_ports)]
    port_values = [item[1] for item in reversed(top_ports)]
    port_pos = list(range(len(port_labels)))
    ax_ports.barh(port_pos, port_values, color="#fb923c")
    ax_ports.set_yticks(port_pos, port_labels)

    ax_exec = figure.add_subplot(gs[1, 8:])
    style_panel(ax_exec)
    ax_exec.text(0.05, 0.90, "Executive readout", transform=ax_exec.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left")
    summary_lines = [
        f"• Blocked packets: {snapshot.blocked_entries}",
        f"• IPv4 vs IPv6: {snapshot.ipv4_events} / {snapshot.ipv6_events}",
        f"• DNS-related hits: {snapshot.dns_attempts}",
        f"• Top protocol: {snapshot.top_protocols[0][0]} ({snapshot.top_protocols[0][1]})" if snapshot.top_protocols else "• Top protocol: n/a",
        f"• Main note: {snapshot.notes[0]}" if snapshot.notes else "• Main note: no additional notes",
    ]
    for idx, line in enumerate(summary_lines):
        ax_exec.text(0.06, 0.74 - idx * 0.13, line, transform=ax_exec.transAxes, color="#cbd5e1", fontsize=11.2, ha="left")

    proto_data = snapshot.top_protocols[:4] or [("none", 0)]
    ax_proto_panel = figure.add_subplot(gs[2, :4])
    ax_proto = style_axis_panel(ax_proto_panel, "Protocol Mix", "Traffic mix in recent firewall events.")
    proto_labels = [item[0] for item in reversed(proto_data)]
    proto_values = [item[1] for item in reversed(proto_data)]
    proto_pos = list(range(len(proto_labels)))
    ax_proto.barh(proto_pos, proto_values, color="#7dd3fc")
    ax_proto.set_yticks(proto_pos, proto_labels)

    iface_data = snapshot.top_inbound_interfaces[:4] or [("none", 0)]
    ax_ifaces_panel = figure.add_subplot(gs[2, 4:8])
    ax_ifaces = style_axis_panel(ax_ifaces_panel, "Inbound Interfaces", "Where blocked traffic arrived.")
    iface_labels = [item[0] for item in reversed(iface_data)]
    iface_values = [item[1] for item in reversed(iface_data)]
    iface_pos = list(range(len(iface_labels)))
    ax_ifaces.barh(iface_pos, iface_values, color="#60a5fa")
    ax_ifaces.set_yticks(iface_pos, iface_labels)

    ax_notes = figure.add_subplot(gs[2, 8:])
    style_panel(ax_notes)
    ax_notes.text(0.05, 0.88, "Context", transform=ax_notes.transAxes, color="#f8fafc", fontsize=16, fontweight="bold", ha="left")
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
        ax_notes.text(0.06, 0.72 - idx * 0.12, f"• {line}", transform=ax_notes.transAxes, color="#cbd5e1", fontsize=11.0, ha="left")

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), bbox_inches="tight", dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
