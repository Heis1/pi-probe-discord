from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pi_probe_discord.firewall import (
    UfwStatus,
    parse_ufw_log_line,
    parse_ufw_status_verbose,
    summarize_entries,
    _read_log_lines,
)


def test_parse_ipv4_tcp_block() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.4 DST=10.0.0.2 LEN=60 TTL=50 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 SYN"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    assert entry.action == "BLOCK"
    assert entry.fields["PROTO"] == "TCP"
    assert entry.fields["DPT"] == "22"


def test_parses_fortiwifi_denied_traffic_syslog() -> None:
    entry = parse_ufw_log_line(
        'date=2026-08-29 time=16:00:00 type="traffic" subtype="forward" srcip=203.0.113.9 srcintf="wan1" dstip=10.10.10.1 dstport=22 proto=6 action="deny"',
        now=datetime(2026, 8, 29, 16, 0, 0),
    )
    assert entry is not None
    assert entry.action == "BLOCK"
    assert entry.fields["SRC"] == "203.0.113.9"
    assert entry.fields["DPT"] == "22"


def test_tracks_accepted_ssh_activity_details() -> None:
    now = datetime.now().astimezone()
    entry = parse_ufw_log_line(
        'date=2026-08-30 time=12:00:00 type="event" ui="ssh(203.0.113.9)" srcip=203.0.113.9 dstip=10.10.10.1 user="admin" srcintf="wan1" action="accept"',
        now=now,
    )
    assert entry is not None
    snapshot = summarize_entries(
        [entry], 24, 5, 10, False, "fortiwifi", True, UfwStatus(active=True, status_line="Status: active")
    )
    assert snapshot.ssh_sessions == 1
    assert snapshot.ssh_session_details[0]["source"] == "203.0.113.9"
    assert snapshot.ssh_session_details[0]["user"] == "admin"


def test_tracks_successful_ssh_login_as_ssh_activity() -> None:
    now = datetime.now().astimezone()
    entry = parse_ufw_log_line(
        'type="event" logdesc="Admin login successful" user="admin" ui="ssh(192.168.1.190)" method="ssh" srcip=192.168.1.190 dstip=10.10.10.1 action="login" status="success"',
        now=now,
    )
    assert entry is not None
    snapshot = summarize_entries(
        [entry], 24, 5, 10, False, "fortiwifi", True, UfwStatus(active=True, status_line="Status: active")
    )
    assert snapshot.auth_successes == 1
    assert snapshot.ssh_sessions == 1


def test_parse_ipv4_udp_block() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC=5.6.7.8 DST=10.0.0.2 LEN=44 TTL=40 PROTO=UDP SPT=5353 DPT=5353"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    assert entry.fields["PROTO"] == "UDP"
    assert entry.fields["DPT"] == "5353"


def test_parse_ipv6_block() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=2001:db8::1 DST=2001:db8::2 LEN=80 PROTO=TCP SPT=443 DPT=55555"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    assert entry.fields["SRC"] == "2001:db8::1"


def test_parse_missing_dpt() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=9.9.9.9 DST=10.0.0.2 LEN=80 PROTO=ICMP"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    assert "DPT" not in entry.fields


def test_multicast_destination_note() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.44 DST=224.0.0.1 LEN=44 PROTO=UDP SPT=5353 DPT=5353"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    snapshot = summarize_entries(
        [entry],
        window_hours=24,
        top_n=5,
        noisy_source_threshold=1,
        include_allow=True,
        log_source="test",
        enabled=True,
        status=UfwStatus(active=True, status_line="Status: active"),
    )
    assert any("multicast" in note.lower() for note in snapshot.notes)


def test_no_log_file_present() -> None:
    snapshot = summarize_entries(
        [],
        window_hours=24,
        top_n=5,
        noisy_source_threshold=10,
        include_allow=False,
        log_source="none",
        enabled=True,
        status=UfwStatus(active=True, status_line="Status: active"),
        log_error="No log files",
    )
    assert snapshot.total_entries == 0
    assert "No recent UFW log entries found" in snapshot.notes[0]


def test_empty_log_file() -> None:
    snapshot = summarize_entries(
        [],
        window_hours=24,
        top_n=5,
        noisy_source_threshold=10,
        include_allow=True,
        log_source="/var/log/ufw.log",
        enabled=True,
        status=UfwStatus(active=True, status_line="Status: active"),
    )
    assert snapshot.total_entries == 0


def test_combines_fortigate_and_ufw_logs_without_duplicate_kernel_log(tmp_path: Path) -> None:
    fortigate = tmp_path / "fortiwifi.log"
    ufw = tmp_path / "ufw.log"
    kernel = tmp_path / "kern.log"
    fortigate.write_text('type="traffic" srcip=203.0.113.9 action="deny"\n', encoding="utf-8")
    ufw.write_text("[UFW BLOCK] SRC=198.51.100.2\n", encoding="utf-8")
    kernel.write_text("duplicate kernel line\n", encoding="utf-8")

    lines, source, error = _read_log_lines([str(fortigate), str(ufw), str(kernel)], 24)

    assert len(lines) == 2
    assert str(fortigate) in source
    assert str(ufw) in source
    assert str(kernel) not in source
    assert error is None


def test_inactive_ufw_status() -> None:
    status = parse_ufw_status_verbose("Status: inactive\n")
    assert status.active is False
