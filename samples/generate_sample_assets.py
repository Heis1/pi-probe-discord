#!/usr/bin/env python3

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
PNG_PATH = ROOT / "speed_chart_example.png"
JSON_PATH = ROOT / "discord_embed_example.json"

WIDTH = 1440
HEIGHT = 1100


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = []
    if bold:
        candidates.extend(
            [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
            ]
        )
    else:
        candidates.extend(
            [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
            ]
        )

    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


FONT_11 = load_font(11)
FONT_14 = load_font(14)
FONT_16 = load_font(16)
FONT_18 = load_font(18)
FONT_24_B = load_font(24, bold=True)
FONT_32_B = load_font(32, bold=True)
FONT_42_B = load_font(42, bold=True)


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int, fill, outline=None, width: int = 1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def metric_card(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], title: str, value: str, subtitle: str, accent):
    rounded(draw, box, 24, fill="#151a22", outline="#212938", width=2)
    x1, y1, x2, y2 = box
    draw.text((x1 + 24, y1 + 18), title, fill="#9aa4b2", font=FONT_14)
    draw.text((x1 + 24, y1 + 48), value, fill="#f3f6fb", font=FONT_24_B)
    draw.text((x1 + 24, y1 + 84), subtitle, fill=accent, font=FONT_14)
    draw.rounded_rectangle((x2 - 24, y1 + 22, x2 - 16, y2 - 22), radius=4, fill=accent)


def map_points(values: list[float], box: tuple[int, int, int, int], y_max: float) -> list[tuple[int, int]]:
    x1, y1, x2, y2 = box
    width = x2 - x1
    height = y2 - y1
    points: list[tuple[int, int]] = []
    for index, value in enumerate(values):
        progress = index / max(len(values) - 1, 1)
        px = x1 + int(progress * width)
        py = y2 - int((value / y_max) * height)
        points.append((px, py))
    return points


def draw_series(draw: ImageDraw.ImageDraw, points: list[tuple[int, int]], color: str):
    if len(points) >= 2:
        draw.line(points, fill=color, width=4)
    for point in points:
        px, py = point
        draw.ellipse((px - 5, py - 5, px + 5, py + 5), fill=color)


def panel_chart(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    subtitle: str,
    labels: list[str],
    download: list[float],
    upload: list[float],
    ping: list[float],
    issue_ranges: list[tuple[int, int]],
):
    rounded(draw, box, 28, fill="#11161f", outline="#202838", width=2)
    x1, y1, x2, y2 = box
    draw.text((x1 + 26, y1 + 20), title, fill="#f3f6fb", font=FONT_24_B)
    draw.text((x1 + 26, y1 + 56), subtitle, fill="#93a0b3", font=FONT_14)

    plot = (x1 + 68, y1 + 105, x2 - 36, y2 - 64)
    px1, py1, px2, py2 = plot

    for start_idx, end_idx in issue_ranges:
        total = max(len(download) - 1, 1)
        issue_x1 = px1 + int((start_idx / total) * (px2 - px1))
        issue_x2 = px1 + int((end_idx / total) * (px2 - px1))
        draw.rounded_rectangle((issue_x1, py1, issue_x2, py2), radius=14, fill="#3a1218")

    for row in range(6):
        y = py1 + int((py2 - py1) * row / 5)
        draw.line((px1, y, px2, y), fill="#232c3b", width=1)
        label = str(int(110 - (110 * row / 5)))
        draw.text((x1 + 18, y - 8), label, fill="#738095", font=FONT_11)

    draw.line((px1, py2, px2, py2), fill="#344055", width=2)
    draw.line((px1, py1, px1, py2), fill="#344055", width=2)

    draw_series(draw, map_points(download, plot, 110), "#39a0ff")
    draw_series(draw, map_points(upload, plot, 110), "#34d399")
    draw_series(draw, map_points(ping, plot, 110), "#ff8a3d")

    for idx, label in enumerate(labels):
        x = px1 + int((idx / max(len(labels) - 1, 1)) * (px2 - px1))
        draw.text((x - 16, py2 + 14), label, fill="#8390a5", font=FONT_11)

    badge_x = x2 - 210
    rounded(draw, (badge_x, y1 + 18, x2 - 26, y1 + 62), 18, fill="#201824", outline="#4b2230", width=1)
    draw.text((badge_x + 16, y1 + 30), "Issue zones highlighted", fill="#ff9fb1", font=FONT_14)


def build_dark_chart():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0e14")
    draw = ImageDraw.Draw(img)

    for top in range(HEIGHT):
        blend = top / HEIGHT
        color = (
            int(10 + 8 * blend),
            int(14 + 11 * blend),
            int(20 + 18 * blend),
        )
        draw.line((0, top, WIDTH, top), fill=color)

    rounded(draw, (24, 24, WIDTH - 24, HEIGHT - 24), 32, fill="#0f141d", outline="#1b2330", width=2)

    draw.text((58, 52), "Internet Health Snapshot", fill="#f4f7fb", font=FONT_42_B)
    draw.text(
        (60, 104),
        "Dark-mode sample designed for instant readability. Red sections indicate clear internet trouble.",
        fill="#93a0b3",
        font=FONT_16,
    )

    rounded(draw, (1130, 46, 1376, 112), 22, fill="#2a1218", outline="#6e1f2f", width=2)
    draw.text((1152, 58), "ATTENTION NEEDED", fill="#ffb4c1", font=FONT_18)
    draw.text((1152, 83), "Latency spike detected", fill="#ffd8df", font=FONT_14)

    metric_y1 = 148
    metric_y2 = 276
    metric_card(draw, (60, metric_y1, 360, metric_y2), "Current Download", "38 Mbps", "Below expected range", "#ff6b6b")
    metric_card(draw, (390, metric_y1, 690, metric_y2), "Current Upload", "6.2 Mbps", "Reduced but usable", "#fbbf24")
    metric_card(draw, (720, metric_y1, 1020, metric_y2), "Current Ping", "182 ms", "High latency", "#ff6b6b")
    metric_card(draw, (1050, metric_y1, 1350, metric_y2), "Overall Status", "Investigate", "Issue obvious at a glance", "#ff6b6b")

    labels_24h = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "23:59"]
    labels_7d = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    download_24 = [92, 94, 91, 88, 42, 38, 41]
    upload_24 = [19, 18, 19, 18, 10, 6, 7]
    ping_24 = [21, 19, 24, 22, 84, 182, 145]

    download_7d = [94, 95, 92, 96, 93, 91, 43]
    upload_7d = [19, 19, 18, 20, 19, 18, 7]
    ping_7d = [20, 19, 21, 18, 20, 22, 141]

    panel_chart(
        draw,
        (60, 320, WIDTH - 60, 660),
        "Last 24 Hours",
        "Healthy through most of the day, then a sharp evening degradation in download and latency.",
        labels_24h,
        download_24,
        upload_24,
        ping_24,
        issue_ranges=[(4, 6)],
    )

    panel_chart(
        draw,
        (60, 700, WIDTH - 60, 1040),
        "Last 7 Days",
        "Stable all week except for a clear outage-quality event on the latest day.",
        labels_7d,
        download_7d,
        upload_7d,
        ping_7d,
        issue_ranges=[(5, 6)],
    )

    legend_y = 1010
    items = [
        ("#39a0ff", "Download Mbps"),
        ("#34d399", "Upload Mbps"),
        ("#ff8a3d", "Ping ms"),
        ("#5d1822", "Problem period"),
    ]
    x = 92
    for color, label in items:
        draw.rounded_rectangle((x, legend_y, x + 28, legend_y + 16), radius=8, fill=color)
        draw.text((x + 40, legend_y - 2), label, fill="#c5cfdd", font=FONT_14)
        x += 250

    img.save(PNG_PATH)


def build_payload():
    payload = {
        "embeds": [
            {
                "title": "⚠️ Pi-hole Report",
                "description": "**Status:** Warning\nInternet performance degraded. The graph makes the problem area obvious.",
                "color": 16766720,
                "fields": [
                    {"name": "Hostname", "value": "`raspberrypi`", "inline": True},
                    {"name": "Date/Time", "value": "2026-04-26 20:15:00 ACST", "inline": True},
                    {"name": "Pi-hole Service", "value": "Running", "inline": True},
                    {"name": "Blocking", "value": "Enabled", "inline": True},
                    {"name": "Gravity Age", "value": "1d old (2026-04-25 03:15:02 ACST)", "inline": True},
                    {"name": "Blocklist", "value": "286412 domains", "inline": True},
                    {
                        "name": "Speed Test",
                        "value": "Download 38.00 Mbps | Upload 6.20 Mbps | Ping 182.00 ms\n- Evening slowdown detected\n- Latency is outside the healthy range",
                        "inline": False,
                    },
                    {
                        "name": "Recent Update Summary",
                        "value": "```text\nNo package updates were available.\n```",
                        "inline": False,
                    },
                ],
                "footer": {"text": "log: /tmp/pihole-update-discord.log"},
                "timestamp": "2026-04-26T10:45:00Z",
            }
        ]
    }
    JSON_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main():
    build_dark_chart()
    build_payload()


if __name__ == "__main__":
    main()
