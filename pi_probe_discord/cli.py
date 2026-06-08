from __future__ import annotations

import sys

from .app import (
    delete_nmap_override,
    render_nmap_devices,
    render_dashboard_check,
    render_dashboard_html,
    render_firewall_chart,
    render_firewall_report,
    run_nmap_scan,
    render_report,
    render_router_report,
    run_dashboard_server,
    run_mode,
    run_router_listener,
    save_nmap_override,
)
from .doctor import run_doctor
from .installer import run_install


def parse_mode(argv: list[str]) -> tuple[str, int | None]:
    if len(argv) >= 2 and argv[1] == "install":
        return "install", None
    if len(argv) >= 2 and argv[1] == "report":
        days = 7
        if len(argv) >= 3:
            try:
                days = max(1, int(argv[2]))
            except ValueError as exc:
                raise ValueError("Usage: pihole_update_report.py report [days]") from exc
        return "report", days
    if len(argv) >= 2 and argv[1] in {
        "full",
        "speedtest-only",
        "update-only",
        "router-listener",
        "dashboard-serve",
        "firewall-chart",
        "dashboard-check",
        "nmap-scan",
        "nmap-devices",
        "nmap-override",
    }:
        return argv[1], None
    if len(argv) >= 2 and argv[1] == "dashboard-html":
        return "dashboard-html", None
    if len(argv) >= 2 and argv[1] == "firewall":
        return "firewall", None
    if len(argv) >= 2 and argv[1] == "router":
        return "router", None
    if len(argv) >= 2 and argv[1] == "doctor":
        return "doctor", None
    if len(argv) >= 2:
        raise ValueError(
            "Usage: pihole_update_report.py [full|speedtest-only|update-only|install|firewall|firewall-chart|router|router-listener|doctor|dashboard-html|dashboard-serve|dashboard-check|nmap-scan|nmap-devices|nmap-override] | report [days]"
        )
    return "full", None


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv
    try:
        mode, report_days = parse_mode(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if mode == "install":
        return run_install(args[2:])
    if mode == "report":
        assert report_days is not None
        print(render_report(report_days))
        return 0
    if mode == "firewall":
        window_hours = None
        as_json = False
        args_tail = args[2:]
        idx = 0
        while idx < len(args_tail):
            token = args_tail[idx]
            if token == "--json":
                as_json = True
            elif token == "--window-hours":
                if idx + 1 >= len(args_tail):
                    print("--window-hours requires a value", file=sys.stderr)
                    return 1
                idx += 1
                try:
                    window_hours = max(1, int(args_tail[idx]))
                except ValueError:
                    print("--window-hours must be an integer", file=sys.stderr)
                    return 1
            else:
                print("Usage: pihole_update_report.py firewall [--window-hours N] [--json]", file=sys.stderr)
                return 1
            idx += 1
        try:
            print(render_firewall_report(window_hours=window_hours, as_json=as_json))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "firewall-chart":
        output_path = args[2] if len(args) >= 3 else None
        try:
            print(render_firewall_chart(output_path=output_path))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "router":
        window_hours = None
        as_json = False
        args_tail = args[2:]
        idx = 0
        while idx < len(args_tail):
            token = args_tail[idx]
            if token == "--json":
                as_json = True
            elif token == "--window-hours":
                if idx + 1 >= len(args_tail):
                    print("--window-hours requires a value", file=sys.stderr)
                    return 1
                idx += 1
                try:
                    window_hours = max(1, int(args_tail[idx]))
                except ValueError:
                    print("--window-hours must be an integer", file=sys.stderr)
                    return 1
            else:
                print("Usage: pihole_update_report.py router [--window-hours N] [--json]", file=sys.stderr)
                return 1
            idx += 1
        try:
            print(render_router_report(window_hours=window_hours, as_json=as_json))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "router-listener":
        try:
            return run_router_listener()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if mode == "dashboard-html":
        output_path = args[2] if len(args) >= 3 else None
        try:
            print(render_dashboard_html(output_path=output_path))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "dashboard-serve":
        try:
            return run_dashboard_server()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if mode == "dashboard-check":
        try:
            print(render_dashboard_check())
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "nmap-scan":
        try:
            return run_nmap_scan()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if mode == "nmap-devices":
        try:
            print(render_nmap_devices())
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "nmap-override":
        args_tail = args[2:]
        if not args_tail or args_tail[0] not in {"set", "clear"}:
            print(
                "Usage: pihole_update_report.py nmap-override set|clear [--ip IP | --mac MAC | --hostname NAME] [--name LABEL] [--category CATEGORY] [--hidden true|false]",
                file=sys.stderr,
            )
            return 1
        action = args_tail[0]
        ip = ""
        mac = ""
        hostname = ""
        name = ""
        category = ""
        hidden = None
        idx = 1
        while idx < len(args_tail):
            token = args_tail[idx]
            if token in {"--ip", "--mac", "--hostname", "--name", "--category", "--hidden"}:
                if idx + 1 >= len(args_tail):
                    print(f"{token} requires a value", file=sys.stderr)
                    return 1
                idx += 1
                value = args_tail[idx]
                if token == "--ip":
                    ip = value
                elif token == "--mac":
                    mac = value
                elif token == "--hostname":
                    hostname = value
                elif token == "--name":
                    name = value
                elif token == "--category":
                    category = value
                else:
                    lowered = value.strip().lower()
                    if lowered not in {"true", "false"}:
                        print("--hidden must be true or false", file=sys.stderr)
                        return 1
                    hidden = lowered == "true"
            else:
                print(
                    "Usage: pihole_update_report.py nmap-override set|clear [--ip IP | --mac MAC | --hostname NAME] [--name LABEL] [--category CATEGORY] [--hidden true|false]",
                    file=sys.stderr,
                )
                return 1
            idx += 1
        try:
            if action == "set":
                print(
                    save_nmap_override(
                        ip=ip,
                        mac=mac,
                        hostname=hostname,
                        name=name,
                        category=category,
                        hidden=hidden,
                    )
                )
            else:
                print(delete_nmap_override(ip=ip, mac=mac, hostname=hostname))
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if mode == "doctor":
        code, output = run_doctor()
        print(output)
        return code

    try:
        return run_mode(mode)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
