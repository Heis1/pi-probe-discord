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
pi-probe-discord network-diagnose
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
PI_PROBE_INTERACTIVE_DASHBOARD_HOST="127.0.0.1"
PI_PROBE_INTERACTIVE_DASHBOARD_PORT="8088"
PI_PROBE_INTERACTIVE_DASHBOARD_TLS_ENABLED="true"
PI_PROBE_INTERACTIVE_DASHBOARD_TLS_CERT_FILE="/etc/pi-probe-discord/dashboard-cert.pem"
PI_PROBE_INTERACTIVE_DASHBOARD_TLS_KEY_FILE="/etc/pi-probe-discord/dashboard-key.pem"
```

Use `8088`. It avoids the usual Pi-hole ports.

Create a certificate and key if you do not already have them:

```bash
sudo openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout /etc/pi-probe-discord/dashboard-key.pem \
  -out /etc/pi-probe-discord/dashboard-cert.pem \
  -days 825 \
  -subj "/CN=$(hostname -f)"
sudo chown root:pi-probe-discord /etc/pi-probe-discord/dashboard-key.pem /etc/pi-probe-discord/dashboard-cert.pem
sudo chmod 640 /etc/pi-probe-discord/dashboard-key.pem /etc/pi-probe-discord/dashboard-cert.pem
```

Generate the HTML once:

```bash
sudo pi-probe-discord dashboard-html
```

Serve the dashboard:

```bash
sudo pi-probe-discord dashboard-serve
```

Keep it running across reboots:

```bash
sudo systemctl enable --now pi-probe-discord-dashboard.service
```

Check the setup:

```bash
pi-probe-discord dashboard-check
```

Open it at:

```text
https://<pi-or-tailscale-name>:8088/
```

If you want browsers to trust the dashboard certificate on your LAN or Tailscale, create or reuse a local CA, sign `/etc/pi-probe-discord/dashboard-cert.pem` with it, and import that CA certificate into the devices that will open the dashboard.

The packaged dashboard service uses `/var/lib/pi-probe-discord/.config/matplotlib` for its cache so it does not emit root-home cache warnings.

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

Expose it beyond localhost only when you intend to:

```bash
PI_PROBE_INTERACTIVE_DASHBOARD_HOST="0.0.0.0"
```

If you keep TLS disabled, use `http://` instead of `https://`.

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
- `/networkdiag`
- `/nmapscan`

Bot env file:

```bash
sudo cp /usr/share/pi-probe-discord/pi-probe-discord-bot.env.example /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chown root:pi-probe-discord /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chmod 640 /etc/pi-probe-discord/pi-probe-discord-bot.env
```

Set:

- `PI_PROBE_DISCORD_BOT_TOKEN`
- `PI_PROBE_DISCORD_ALLOWED_USER_IDS`

Start the bot:

```bash
sudo systemctl enable --now pi-probe-discord-bot.service
journalctl -u pi-probe-discord-bot.service -n 50 --no-pager
```
The packaged bot runs as a systemd-managed root service so it can trigger local reports and timers directly.

## Router SNMP listener

The packaged SNMP listener binds UDP port `162` directly. Because this is a privileged port, the packaged service runs as `root` and writes state into `/var/lib/pi-probe-discord`.

Check the listener:

```bash
sudo systemctl status pi-probe-discord-snmp-listener.service --no-pager
sudo ss -lunp | grep ':162'
sudo pi-probe-discord router
```

TP-Link side:

- enable SNMP trap sending, not just SNMP polling
- set the trap destination host to the Pi IP, for example `192.168.1.51`
- set the trap destination UDP port to `162`
- trigger a test trap or a real link event, then rerun `sudo pi-probe-discord router`

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
sudo pi-probe-discord-update 1.0.0
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
