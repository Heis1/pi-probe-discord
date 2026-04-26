from __future__ import annotations

import sys

from .app import render_report, run_mode
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
    if len(argv) >= 2:
        raise ValueError("Usage: pihole_update_report.py [full|speedtest-only|update-only|install] | report [days]")
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

    try:
        return run_mode(mode)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

