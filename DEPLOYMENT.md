# Deployment

This is the shortest reliable way to set up `pi-probe-discord` on a Pi.

## Fresh install on a Pi

1. Copy or clone the repo to the Pi.
2. Install the package or run the installer.
3. Set the Discord webhook.
4. Enable the timers.

## Package install

If you already have a built `.deb`:

```bash
sudo apt install /path/to/pi-probe-discord_<version>-1_all.deb
sudo systemctl daemon-reload
sudo systemctl restart pi-probe-discord-speedtest.timer pi-probe-discord-full.timer
```

If you are pulling from GitHub releases:

```bash
sudo pi-probe-discord-update latest
```

## Required config

Edit:

```bash
sudo nano /etc/pi-probe-discord/pihole-update-discord.env
```

Set at least:

```bash
WEBHOOK_URL="https://discord.com/api/webhooks/replace/this"
```

## Enable timers

```bash
sudo systemctl enable --now pi-probe-discord-speedtest.timer
sudo systemctl enable --now pi-probe-discord-full.timer
```

## Manual checks

```bash
pi-probe-discord speedtest-only
pi-probe-discord full
pi-probe-discord doctor
```

## Optional bot

Create bot config:

```bash
sudo cp /usr/share/pi-probe-discord/pi-probe-discord-bot.env.example /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chown root:pi-probe-discord /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chmod 640 /etc/pi-probe-discord/pi-probe-discord-bot.env
```

Set:

- `PI_PROBE_DISCORD_BOT_TOKEN`
- `PI_PROBE_DISCORD_ALLOWED_USER_IDS`

Enable:

```bash
sudo systemctl enable --now pi-probe-discord-bot.service
```

Check:

```bash
journalctl -u pi-probe-discord-bot.service -n 50 --no-pager
```

The packaged bot runs as a systemd-managed root service so it can trigger local reports and timers directly.

## Optional premium and interactive dashboards

Add to `/etc/pi-probe-discord/pihole-update-discord.env`:

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

Self-signed example:

```bash
sudo openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout /etc/pi-probe-discord/dashboard-key.pem \
  -out /etc/pi-probe-discord/dashboard-cert.pem \
  -days 825 \
  -subj "/CN=$(hostname -f)"
sudo chown root:pi-probe-discord /etc/pi-probe-discord/dashboard-key.pem /etc/pi-probe-discord/dashboard-cert.pem
sudo chmod 640 /etc/pi-probe-discord/dashboard-key.pem /etc/pi-probe-discord/dashboard-cert.pem
```

Serve the HTML dashboard:

```bash
pi-probe-discord dashboard-serve
```

Open:

```text
https://<pi-or-tailscale-name>:8088/index.html
```

## Upgrade behavior

The package upgrade path now:

- reloads systemd
- restarts speedtest and full timers
- restarts the bot service if enabled or active
- restarts the SNMP listener if enabled or active

## Troubleshooting

```bash
journalctl -u pi-probe-discord-speedtest.service -n 100 --no-pager
journalctl -u pi-probe-discord-full.service -n 100 --no-pager
journalctl -u pi-probe-discord-bot.service -n 100 --no-pager
```
