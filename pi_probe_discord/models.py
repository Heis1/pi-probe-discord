from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AppConfig:
    webhook_url: str
    config_file: str
    log_file: str
    chart_file: str
    db_path: str
    history_retention_days: int
    request_timeout: int
    max_text_field_length: int
    speedtest_schedule_minutes: int
    full_report_schedule: str


@dataclass
class UpdateResult:
    ok: bool
    summary: str
    error: str = ""
    packages: list[str] = field(default_factory=list)


@dataclass
class PiholeResult:
    service_status: str = "Unknown"
    blocking_status: str = "Unknown"
    gravity_age: str = "Unavailable"
    blocklist_count: str = "Unavailable"
    update_status: str = "Unknown"
    warnings: list[str] = field(default_factory=list)


@dataclass
class SpeedResult:
    ok: bool
    summary: str
    download_mbps: float | None = None
    upload_mbps: float | None = None
    ping_ms: float | None = None
    chart_generated: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class RunRecord:
    recorded_at: datetime
    hostname: str
    update_ok: bool
    update_summary: str
    update_error: str
    pihole_service_status: str
    pihole_blocking_status: str
    pihole_gravity_age: str
    pihole_blocklist_count: str
    pihole_warnings: str
    speed_ok: bool
    speed_summary: str
    download_mbps: float | None
    upload_mbps: float | None
    ping_ms: float | None
    speed_warnings: str
