from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests


def post_bot_report(config: Any, payload: dict[str, Any], chart_file: str | None = None) -> None:
    """Post directly to Discord's REST API so scheduled reports do not compete with the live bot gateway session."""
    if not config.discord_bot_token or not config.discord_report_channel_id:
        raise RuntimeError("Discord bot token or report channel ID is not configured.")
    endpoint = f"https://discord.com/api/v10/channels/{config.discord_report_channel_id}/messages"
    headers = {"Authorization": f"Bot {config.discord_bot_token}"}
    embeds = payload.get("embeds") or []
    if chart_file and Path(chart_file).exists():
        with Path(chart_file).open("rb") as handle:
            response = requests.post(
                endpoint,
                headers=headers,
                data={"payload_json": json.dumps({"embeds": embeds})},
                files={"files[0]": (Path(chart_file).name, handle, "image/png")},
                timeout=20,
            )
    else:
        response = requests.post(endpoint, headers={**headers, "Content-Type": "application/json"}, json={"embeds": embeds}, timeout=20)
    response.raise_for_status()
