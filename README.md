# pi-probe-discord

`pi-probe-discord` runs internet checks on a Pi, stores local history in SQLite, and posts results to Discord.

## What it does

- scheduled speed tests
- Discord embeds with health verdicts
- standard 24h/7d/30d chart image
- optional premium dashboard image for Discord
- optional interactive HTML dashboard for local or Tailscale access
- optional visual firewall snapshot for firewall alerts
- Pi-hole, firewall, router SNMP, and update reporting

## Quick start

Install or upgrade the package on the Pi:

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
pi-probe-discord doctor
```

## Dashboard options

Set in `/etc/pi-probe-discord/pihole-update-discord.env`:

```bash
PI_PROBE_DASHBOARD_STYLE="standard"
PI_PROBE_FIREWALL_CHART_FILE="/var/lib/pi-probe-discord/firewall_snapshot.png"
PI_PROBE_INTERACTIVE_DASHBOARD_ENABLED="false"
PI_PROBE_INTERACTIVE_DASHBOARD_FILE="/var/lib/pi-probe-discord/dashboard/index.html"
PI_PROBE_INTERACTIVE_DASHBOARD_HOST="0.0.0.0"
PI_PROBE_INTERACTIVE_DASHBOARD_PORT="8088"
```

Use `PI_PROBE_DASHBOARD_STYLE="premium"` to post the premium dashboard image to Discord.

Use `PI_PROBE_INTERACTIVE_DASHBOARD_ENABLED="true"` to refresh the HTML dashboard on each successful speed/full run.

Serve the HTML dashboard:

```bash
pi-probe-discord dashboard-serve
```

Then open:

```text
http://<pi-or-tailscale-name>:8088/index.html
```

## Discord bot

The optional bot supports:

- `/speedtest`
- `/fullreport`
- `/firewall`
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

## Speedtest failures

If the Python speedtest client fails, the app now attempts a `speedtest-cli --json` fallback before reporting failure.

If the speed test still cannot complete, Discord should now show a clear `Speed Test Failed` state instead of an `Internet Slower Than Usual` verdict.

## Important files

- config: `/etc/pi-probe-discord/pihole-update-discord.env`
- bot config: `/etc/pi-probe-discord/pi-probe-discord-bot.env`
- data: `/var/lib/pi-probe-discord/pi_probe_discord.db`
- standard chart image: `/var/lib/pi-probe-discord/speed_chart.png`
- interactive dashboard default: `/var/lib/pi-probe-discord/dashboard/index.html`

## Upgrade

```bash
sudo pi-probe-discord-update latest
```

Or a specific version:

```bash
sudo pi-probe-discord-update 0.1.22
```

The upgrade helper now reloads systemd, restarts timers, and restarts the bot service if it is enabled or active.

## Troubleshooting

Bot logs:

```bash
journalctl -u pi-probe-discord-bot.service -n 100 --no-pager
```

Speed test service logs:

```bash
journalctl -u pi-probe-discord-speedtest.service -n 100 --no-pager
```

Full report service logs:

```bash
journalctl -u pi-probe-discord-full.service -n 100 --no-pager
```

If chart rendering fails, the app still posts a text embed when it can.

## More detail

For a fuller Pi setup flow, see [DEPLOYMENT.md](DEPLOYMENT.md).
