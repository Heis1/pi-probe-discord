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


def _ellipsize(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)].rstrip() + "…"


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


def _field(value: Any, name: str, default: Any = "") -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _device_lookup(devices: list[Any] | None) -> dict[str, Any]:
    return {str(_field(device, "ip")): device for device in devices or [] if _field(device, "ip")}


def _device_name(device: Any | None, source: str) -> str:
    if device is None:
        return "Unknown LAN device" if _classify_source(source) == "LAN" else "Unknown source"
    return str(_field(device, "name") or _field(device, "hostname") or source)


def _device_meta(device: Any | None) -> str:
    if device is None:
        return "No inventory match - check DHCP lease or run a fresh scan"
    vendor = str(_field(device, "vendor") or "")
    parts = [
        str(_field(device, "category_label") or _field(device, "categoryLabel") or "Unknown"),
    ]
    if vendor:
        parts.append(vendor)
    services = _field(device, "services", []) or []
    clean_services = [str(service) for service in services if str(service).lower() != "unknown"]
    if clean_services:
        parts.append("svc " + "/".join(clean_services[:3]))
    else:
        ports = _field(device, "open_ports", None) or _field(device, "openPorts", []) or []
        if ports:
            parts.append("ports " + "/".join(str(port) for port in ports[:4]))
        else:
            mac = str(_field(device, "mac") or "")
            if mac:
                parts.append(f"MAC {mac}")
    return _ellipsize(" | ".join(parts), 76)


def _source_row(
    ax: Any,
    y: float,
    rank: int,
    source: str,
    value: int,
    max_value: int,
    device: Any | None,
) -> None:
    source_kind = _classify_source(source)
    name = _device_name(device, source)
    known_color = TEXT if device is not None else WARN
    ax.text(0.05, y, str(rank), color=FAINT, fontsize=12, fontweight="bold", ha="left", va="center")
    ax.text(0.12, y + 0.025, name, color=known_color, fontsize=12.5, fontweight="bold", ha="left", va="center")
    ax.text(0.12, y - 0.025, f"{source} ({source_kind})", color=MUTED, fontsize=10.2, ha="left", va="center")
    ax.text(0.92, y + 0.012, str(value), color=TEXT, fontsize=13, ha="right", va="center")
    ax.text(0.12, y - 0.075, _device_meta(device), color=FAINT, fontsize=8.6, ha="left", va="center")
    bar_width = 0.76 * (value / max(max_value, 1))
    ax.add_patch(Rectangle((0.12, y - 0.115), bar_width, 0.014, color=BLUE, linewidth=0))


def _private_source_ratio(snapshot: FirewallSnapshot) -> float:
    total = sum(count for _source, count in snapshot.top_sources)
    if total <= 0:
        return 0.0
    private = sum(count for source, count in snapshot.top_sources if _classify_source(source) in {"LAN", "loopback", "link-local"})
    return private / total


def _build_assessment(snapshot: FirewallSnapshot, devices_by_ip: dict[str, Any] | None = None) -> tuple[str, str, str, str]:
    devices_by_ip = devices_by_ip or {}
    private_ratio = _private_source_ratio(snapshot)
    top_source = snapshot.top_sources[0] if snapshot.top_sources else ("none", 0)
    top_source_kind = _classify_source(top_source[0])
    top_name = _device_name(devices_by_ip.get(top_source[0]), top_source[0])

    if snapshot.ssh_attempts > 0:
        return (
            "Investigate SSH probing",
            "Port 22 attempts were blocked in this window.",
            "Confirm SSH is not exposed unexpectedly; keep the source blocked unless it is yours.",
            ORANGE,
        )
    if private_ratio >= 0.90 and top_source_kind in {"LAN", "loopback", "link-local"}:
        return (
            "LAN noise, low risk",
            "Top blocked sources are private LAN addresses and there are no SSH attempts.",
            f"Confirm {top_name} ({top_source[0]}); if trusted, tune or ignore this noise instead of treating it as an attack.",
            "#5eead4",
        )
    if snapshot.noisy_sources:
        return (
            "Repeated source activity",
            "One or more sources crossed the noisy-source threshold.",
            "Check whether the top source is expected; block or investigate it if unknown.",
            WARN,
        )
    return (
        "Routine blocking",
        "Blocked entries are present, but no strong attack signal stands out.",
        "No immediate action. Recheck if volume or source mix changes.",
        "#5eead4",
    )


def generate_firewall_chart(snapshot: FirewallSnapshot, chart_path: str, devices: list[Any] | None = None) -> tuple[bool, str]:
    if plt is None or Rectangle is None:
        return False, "matplotlib not installed"

    devices_by_ip = _device_lookup(devices)
    decision, why, action, decision_color = _build_assessment(snapshot, devices_by_ip)

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

    figure = plt.figure(figsize=(13.6, 9.2), facecolor=BG)

    ax_title = figure.add_axes([0.04, 0.89, 0.92, 0.09])
    _panel(ax_title)
    ax_title.set_facecolor(BG)
    ax_title.text(0.00, 0.76, "Firewall Snapshot", color=TEXT, fontsize=22, fontweight="bold", ha="left", va="center")
    ax_title.text(0.00, 0.20, f"Window {snapshot.window_hours}h | source {snapshot.log_source}", color=MUTED, fontsize=10.5, ha="left", va="center")

    ax_status = figure.add_axes([0.04, 0.75, 0.92, 0.12])
    _panel(ax_status)
    ax_status.text(0.035, 0.62, verdict.upper(), color=verdict_color, fontsize=20, fontweight="bold", ha="left", va="center")
    ax_status.text(0.035, 0.31, verdict_detail, color=TEXT, fontsize=10.8, ha="left", va="center")
    _metric(ax_status, 0.42, "Blocked", str(snapshot.blocked_entries), "UFW BLOCK entries")
    _metric(ax_status, 0.62, "Noisy sources", str(len(snapshot.noisy_sources)), "over threshold", WARN)
    _metric(ax_status, 0.82, "SSH attempts", str(snapshot.ssh_attempts), "DPT=22 hits", ORANGE)

    ax_sources = figure.add_axes([0.04, 0.34, 0.55, 0.36])
    _panel(ax_sources)
    ax_sources.text(0.05, 0.90, "Noisy Devices", color=TEXT, fontsize=19, fontweight="bold", ha="left", va="center")
    ax_sources.text(0.05, 0.80, "Top firewall sources matched against Nmap inventory", color=MUTED, fontsize=10.5, ha="left", va="center")
    top_sources = snapshot.top_sources[:4] or [("none", 0)]
    source_max = max(count for _source, count in top_sources)
    y = 0.68
    for idx, (source, count) in enumerate(top_sources, start=1):
        _source_row(ax_sources, y, idx, source, count, source_max, devices_by_ip.get(source))
        y -= 0.19

    ax_ports = figure.add_axes([0.62, 0.34, 0.34, 0.36])
    _panel(ax_ports)
    ax_ports.text(0.06, 0.90, "Top Ports", color=TEXT, fontsize=19, fontweight="bold", ha="left", va="center")
    ax_ports.text(0.06, 0.80, "Blocked destinations", color=MUTED, fontsize=10.5, ha="left", va="center")
    top_ports = snapshot.top_ports[:5] or [("none", 0)]
    port_max = max(count for _port, count in top_ports)
    y = 0.65
    for idx, (port, count) in enumerate(top_ports, start=1):
        _table_row(ax_ports, y, idx, port, count, port_max, ORANGE)
        y -= 0.12

    ax_summary = figure.add_axes([0.04, 0.07, 0.92, 0.21])
    _panel(ax_summary)
    top_source = snapshot.top_sources[0] if snapshot.top_sources else ("none", 0)
    top_port = snapshot.top_ports[0] if snapshot.top_ports else ("none", 0)
    protocol = f"{snapshot.top_protocols[0][0]} ({snapshot.top_protocols[0][1]})" if snapshot.top_protocols else "n/a"
    interfaces = ", ".join(f"{name}:{count}" for name, count in snapshot.top_inbound_interfaces[:2]) or "none"
    known_sources = [f"{_device_name(devices_by_ip.get(source), source)} ({source})" for source, _ in snapshot.top_sources[:3]]
    unknown_sources = [source for source, _ in snapshot.top_sources[:5] if source not in devices_by_ip]
    evidence = f"Top port {top_port[0]} ({top_port[1]}); protocol {protocol}; interfaces {interfaces}; IPv4/IPv6 {snapshot.ipv4_events}/{snapshot.ipv6_events}."
    ax_summary.text(0.035, 0.80, "Assessment", color=TEXT, fontsize=15, fontweight="bold", ha="left", va="center")
    ax_summary.text(0.19, 0.80, decision, color=decision_color, fontsize=15, fontweight="bold", ha="left", va="center")
    ax_summary.text(0.035, 0.58, _wrap(f"Why: {why}", 130), color=TEXT, fontsize=10.8, ha="left", va="center")
    ax_summary.text(0.035, 0.39, _wrap(f"Action: {action}", 130), color=MUTED, fontsize=10.8, ha="left", va="center")
    inventory_note = "Known: " + "; ".join(known_sources)
    if unknown_sources:
        inventory_note += f". Unknown: {', '.join(unknown_sources)}"
    ax_summary.text(0.035, 0.22, _wrap(inventory_note, 145), color=FAINT, fontsize=9.0, ha="left", va="center")
    ax_summary.text(0.035, 0.10, _wrap(evidence, 150), color=FAINT, fontsize=8.3, ha="left", va="center")

    output = Path(chart_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor=figure.get_facecolor(), dpi=160)
    plt.close(figure)
    return True, "Firewall chart generated"
