from __future__ import annotations

import sys

from .app import render_firewall_report, render_report, run_mode
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
    if len(argv) >= 2 and argv[1] in {"full", "speedtest-only", "update-only"}:
        return argv[1], None
    if len(argv) >= 2 and argv[1] == "firewall":
        return "firewall", None
    if len(argv) >= 2:
        raise ValueError("Usage: pihole_update_report.py [full|speedtest-only|update-only|install|firewall] | report [days]")
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
        print(render_firewall_report(window_hours=window_hours, as_json=as_json))
        return 0

    try:
        return run_mode(mode)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
