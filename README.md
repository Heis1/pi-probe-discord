# pi-probe-discord

`pi-probe-discord` runs internet checks on a Pi, stores local history in SQLite, and posts results to Discord.

## What it does

- scheduled speed tests and full reports
- Discord embeds with health verdicts and PNG snapshots
- optional premium dashboard PNG for Discord
- optional interactive HTML dashboard for local, LAN, or Tailscale access
- optional firewall, Pi-hole, router SNMP, and update reporting

## Quick start

Install or upgrade:

```bash
sudo pi-probe-discord-update latest
```

Edit config:

```bash
sudo nano /etc/pi-probe-discord/pihole-update-discord.env
```

Minimum required setting:

```bash
WEBHOOK_URL="https://discord.com/api/webhooks/replace/this"
```

Health check:

```bash
sudo pi-probe-discord doctor
```

## Common commands

```bash
pi-probe-discord full
pi-probe-discord speedtest-only
pi-probe-discord report 7
pi-probe-discord firewall
pi-probe-discord router
pi-probe-discord dashboard-html
pi-probe-discord dashboard-serve
pi-probe-discord dashboard-check
pi-probe-discord doctor
```

## Dashboard setup

Recommended dashboard settings in `/etc/pi-probe-discord/pihole-update-discord.env`:

```bash
PI_PROBE_DASHBOARD_STYLE="premium"
PI_PROBE_INTERACTIVE_DASHBOARD_ENABLED="true"
PI_PROBE_INTERACTIVE_DASHBOARD_FILE="/var/lib/pi-probe-discord/dashboard/index.html"
PI_PROBE_INTERACTIVE_DASHBOARD_HOST="0.0.0.0"
PI_PROBE_INTERACTIVE_DASHBOARD_PORT="8088"
```

Use `8088`. It avoids the usual Pi-hole ports.

Generate the HTML once:

```bash
sudo pi-probe-discord dashboard-html
```

Serve the dashboard:

```bash
sudo pi-probe-discord dashboard-serve
```

Check the setup:

```bash
pi-probe-discord dashboard-check
```

Open it at:

```text
http://<pi-or-tailscale-name>:8088/
```

The dashboard server also exposes:

- `/healthz`
- `/status.json`

## Firewall examples

LAN-only example:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8088 proto tcp comment 'pi-probe dashboard'
```

Tailscale example:

```bash
sudo ufw allow in on tailscale0 to any port 8088 proto tcp comment 'pi-probe dashboard tailscale'
```

## Discord dashboard link

If the dashboard is reachable from the Discord viewers, set:

```bash
PI_PROBE_PUBLIC_DASHBOARD_URL="https://example.com/pi-probe/"
PI_PROBE_DASHBOARD_LINK_LABEL="Open Interactive Dashboard"
```

When `PI_PROBE_PUBLIC_DASHBOARD_URL` is set, Discord posts keep the PNG image and also add the dashboard link in the embed.

## Optional router event overlay

Optional files:

- `/var/lib/pi-probe-discord/events/router_events.csv`
- `/var/lib/pi-probe-discord/events/router_events.json`

CSV example:

```csv
timestamp,event_type,message,severity,source
2026-06-06T10:00:00,wan_disconnect,Carrier lost,critical,router
2026-06-06T10:02:00,link_up,WAN recovered,info,router
```

JSON example:

```json
[
  {
    "timestamp": "2026-06-06T10:00:00",
    "event_type": "wan_disconnect",
    "message": "Carrier lost",
    "severity": "critical",
    "source": "router"
  }
]
```

If neither file exists, the dashboard still works normally.

## Optional Pi-hole hourly correlation

Optional file:

- `/var/lib/pi-probe-discord/pihole/pihole_hourly.csv`

Example:

```csv
datetime,dns_queries,blocked_queries,blocked_percent
2026-06-06T10:00:00,1200,210,17.5
2026-06-06T11:00:00,1320,240,18.2
```

If the file is missing, the dashboard hides the correlation chart and shows a clean empty-state message.

## Discord bot

The optional bot supports:

- `/speedtest`
- `/fullreport`
- `/firewall` (visual snapshot when chart rendering is available, text fallback otherwise)
- `/router`

Bot env file:

```bash
sudo cp /usr/share/pi-probe-discord/pi-probe-discord-bot.env.example /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chmod 600 /etc/pi-probe-discord/pi-probe-discord-bot.env
```

Set:

- `PI_PROBE_DISCORD_BOT_TOKEN`
- `PI_PROBE_DISCORD_ALLOWED_USER_IDS`

Start the bot:

```bash
sudo systemctl enable --now pi-probe-discord-bot.service
journalctl -u pi-probe-discord-bot.service -n 50 --no-pager
```

If you run the bot as a non-root user, use the sudoers template at:

```text
/usr/share/pi-probe-discord/pi-probe-discord-bot.sudoers.example
```

## Important files

- config: `/etc/pi-probe-discord/pihole-update-discord.env`
- bot config: `/etc/pi-probe-discord/pi-probe-discord-bot.env`
- data: `/var/lib/pi-probe-discord/pi_probe_discord.db`
- chart image: `/var/lib/pi-probe-discord/speed_chart.png`
- dashboard HTML: `/var/lib/pi-probe-discord/dashboard/index.html`
- dashboard status: `/var/lib/pi-probe-discord/dashboard/status.json`

## Upgrade

```bash
sudo pi-probe-discord-update latest
```

Or a specific version:

```bash
sudo pi-probe-discord-update 0.1.26
```

## Troubleshooting

Bot logs:

```bash
journalctl -u pi-probe-discord-bot.service -n 100 --no-pager
```

Speed test logs:

```bash
journalctl -u pi-probe-discord-speedtest.service -n 100 --no-pager
```

Full report logs:

```bash
journalctl -u pi-probe-discord-full.service -n 100 --no-pager
```

If chart rendering fails, the app still posts a text embed when it can.

## More detail

For the fuller Pi setup flow, see `DEPLOYMENT.md`.
