from __future__ import annotations

from datetime import datetime

from pi_probe_discord.firewall import (
    UfwStatus,
    parse_ufw_log_line,
    parse_ufw_status_verbose,
    summarize_entries,
)


def test_parse_ipv4_tcp_block() -> None:
    now = datetime(2026, 5, 2, 12, 0, 0)
    line = "May  2 11:58:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.4 DST=10.0.0.2 LEN=60 TTL=50 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 SYN"
    entry = parse_ufw_log_line(line, now=now)
    assert entry is not None
    assert entry.action == "BLOCK"
    assert entry.fields["PROTO"] == "TCP"
    assert entry.fields["DPT"] == "22"


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


def test_inactive_ufw_status() -> None:
    status = parse_ufw_status_verbose("Status: inactive\n")
    assert status.active is False
