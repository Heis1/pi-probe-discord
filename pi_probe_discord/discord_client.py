from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from .models import AppConfig, PiholeResult, SpeedResult, UpdateResult
from .status import assess_internet_health


def build_embed(
    config: AppConfig,
    hostname: str,
    run_at_local: str,
    history: dict[str, list[dict[str, Any]]],
    update_result: UpdateResult,
    pihole_result: PiholeResult,
    speed_result: SpeedResult,
    probe_version_line: str | None = None,
) -> dict[str, Any]:
    warnings: list[str] = []
    warnings.extend(pihole_result.warnings)
    warnings.extend(speed_result.warnings)

    latest_time = history["download"][-1]["x"] if history.get("download") else ""
    if latest_time:
        try:
            assessment = assess_internet_health(history, datetime.fromisoformat(latest_time), speed_result)
        except ValueError:
            assessment = assess_internet_health(history, datetime.now().astimezone(), speed_result)
    else:
        assessment = assess_internet_health(history, datetime.now().astimezone(), speed_result)

    plain_summary = {
        "INTERNET HEALTHY": "Internet looks normal right now.",
        "INTERNET SLOWER THAN NORMAL": "Internet is working, but slower than your usual range.",
        "INTERNET DEGRADED": "Internet problem detected right now.",
        "WAITING FOR DATA": "Still building enough local history to judge the connection.",
    }.get(assessment.label, assessment.headline)

    title = (
        "✅ Internet Looks Normal" if assessment.discord_color == 3066993 else
        "⚠️ Internet Slower Than Usual" if assessment.discord_color == 16766720 else
        "❌ Internet Problem Detected"
    )
    color = assessment.discord_color
    description = plain_summary
    if not update_result.ok:
        title = "❌ Update Failed"
        color = 15158332
        description = f"Update failed: {update_result.error}"
    elif warnings:
        description += "\nAdditional warnings were recorded."

    speed_value = speed_result.summary
    if warnings:
        speed_value += "\n" + "\n".join(f"- {item}" for item in warnings[:5])

    return {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "fields": [
                    {"name": "What This Means", "value": assessment.headline[:1024], "inline": False},
                    {"name": "Now", "value": speed_value[:1024], "inline": False},
                    {"name": "Pi-hole", "value": f"Service: {pihole_result.service_status}\nBlocking: {pihole_result.blocking_status}", "inline": True},
                    {"name": "Host", "value": f"`{hostname}`\n{run_at_local}", "inline": True},
                    {"name": "Why It Was Flagged", "value": assessment.detail[:1024], "inline": True},
                    {"name": "Gravity / Blocklist", "value": f"{pihole_result.gravity_age}\n{pihole_result.blocklist_count}", "inline": False},
                    {"name": "Probe Version", "value": (probe_version_line or "Version check not run")[:1024], "inline": False},
                    {"name": "Recent Update Summary", "value": f"```text\n{update_result.summary[:900]}\n```", "inline": False},
                ],
                "footer": {"text": f"log: {config.log_file}"},
            }
        ]
    }


def post_webhook_json(config: AppConfig, payload: dict[str, Any]) -> None:
    response = requests.post(config.webhook_url, json=payload, timeout=config.request_timeout)
    response.raise_for_status()


def post_webhook_file(config: AppConfig, payload_json: dict[str, Any], image_path: str) -> None:
    with Path(image_path).open("rb") as image_handle:
        response = requests.post(
            config.webhook_url,
            data={"payload_json": json.dumps(payload_json)},
            files={"file": (Path(image_path).name, image_handle, "image/png")},
            timeout=config.request_timeout,
        )
    response.raise_for_status()
