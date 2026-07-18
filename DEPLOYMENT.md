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
sudo systemctl restart pi-probe-discord-speedtest.timer pi-probe-discord-full.timer pi-probe-discord-nmap.timer
sudo systemctl restart pi-probe-discord-dashboard.service
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

Useful dashboard and inventory settings:

```bash
PI_PROBE_DASHBOARD_REFRESH_SECONDS="60"
PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN=""
PI_PROBE_NMAP_SCAN_MINUTES="360"
```

## Enable timers

```bash
sudo systemctl enable --now pi-probe-discord-speedtest.timer
sudo systemctl enable --now pi-probe-discord-full.timer
sudo systemctl enable --now pi-probe-discord-nmap.timer
```

## Manual checks

```bash
pi-probe-discord speedtest-only
pi-probe-discord full
sudo pi-probe-discord nmap-scan
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

Keep it persistent:

```bash
sudo systemctl enable --now pi-probe-discord-dashboard.service
```

Open:

```text
https://<pi-or-tailscale-name>:8088/index.html
```

The dashboard page polls `/api/dashboard/data` every `PI_PROBE_DASHBOARD_REFRESH_SECONDS` seconds by default. That refresh only reloads dashboard JSON. It does not run an Nmap scan. Manual Nmap scans still go through the protected scan action and refresh the page data only after the scan completes.

## Bambu Lab printers

Nmap inventory processing now identifies Bambu Lab printers from certificate and service evidence. A certificate issuer such as `BBL Technologies Co. Ltd`, `BBL Device CA`, or `BBL CA` produces a confirmed `Bambu Lab 3D Printer` classification. Supporting service evidence, such as FTPS on `990` plus Bambu control ports `3000` and `6000`, can raise a probable match without over-classifying generic port `3000` services.

The dashboard shows confirmed printers with a printer marker, confidence, evidence summary, and `Device ID` when the certificate CN is already present in scan data.

## Automated topology discovery

The dashboard can now build a live topology diagram from SNMP bridge MAC tables.

Install the collector dependency on the Pi:

```bash
sudo apt install snmp
```

Example configuration:

```bash
PI_PROBE_TOPOLOGY_ENABLED="true"
PI_PROBE_TOPOLOGY_NODES_JSON='[
  {"id":"router","name":"Main Router","host":"192.168.1.1","management_ip":"192.168.1.1","community":"public","role":"router","location":"Main Network"},
  {"id":"extender","name":"Downstairs Extender","host":"192.168.1.115","management_ip":"192.168.1.115","community":"public","role":"extender","location":"Downstairs"}
]'
PI_PROBE_TOPOLOGY_CACHE_JSON="/var/lib/pi-probe-discord/topology/latest.json"
PI_PROBE_TOPOLOGY_REFRESH_MINUTES="30"
PI_PROBE_TOPOLOGY_SNMPWALK_BIN="snmpwalk"
PI_PROBE_TOPOLOGY_SNMP_TIMEOUT_SECONDS="6"
```

This topology refresh is separate from dashboard polling. The browser refreshing `/api/dashboard/data` does not itself run Nmap or SNMP collection.

## Root-only router web UI credentials

If you later enable router web UI scraping, keep the credentials in a separate root-only file instead of `/etc/pi-probe-discord/pihole-update-discord.env`.

Main env:

```bash
PI_PROBE_ROUTER_WEBUI_ENABLED="true"
PI_PROBE_ROUTER_WEBUI_URL="http://192.168.1.1"
PI_PROBE_ROUTER_WEBUI_SECRET_FILE="/etc/pi-probe-discord/router-webui.env"
PI_PROBE_ROUTER_WEBUI_CA_FILE="/etc/pi-probe-discord/router-webui-ca.pem"
```

Install the secret template and lock it down:

```bash
sudo install -o root -g root -m 600 /usr/share/pi-probe-discord/router-webui.env.example /etc/pi-probe-discord/router-webui.env
sudo nano /etc/pi-probe-discord/router-webui.env
```

The secret file must remain owned by `root` with mode `600` or Pi Probe will refuse to load it.

To pin the router TLS certificate, save the router certificate to:

```bash
/etc/pi-probe-discord/router-webui-ca.pem
```

With `PI_PROBE_ROUTER_WEBUI_CA_FILE` set, router web UI scraping verifies the router certificate instead of accepting any certificate from the LAN.

## Nmap timer inspection and logs

```bash
sudo systemctl status pi-probe-discord-nmap.timer --no-pager
sudo systemctl list-timers pi-probe-discord-nmap.timer --all
sudo systemctl cat pi-probe-discord-nmap.timer
sudo journalctl -u pi-probe-discord-nmap.service -n 100 --no-pager
```

## Upgrade behavior

The package upgrade path now:

- reloads systemd
- restarts speedtest and full timers
- regenerates the Nmap timer override from `PI_PROBE_NMAP_SCAN_MINUTES`
- restarts the Nmap timer if it is enabled or active
- restarts the bot service if enabled or active
- restarts the dashboard service if enabled or active
- restarts the SNMP listener if enabled or active

## Optional router SNMP listener

The packaged listener binds UDP `162` directly and runs as `root` so routers can send traps without extra port-redirection work.

Check it with:

```bash
sudo systemctl status pi-probe-discord-snmp-listener.service --no-pager
sudo ss -lunp | grep ':162'
sudo pi-probe-discord router
```

## Troubleshooting

```bash
journalctl -u pi-probe-discord-speedtest.service -n 100 --no-pager
journalctl -u pi-probe-discord-full.service -n 100 --no-pager
journalctl -u pi-probe-discord-nmap.service -n 100 --no-pager
journalctl -u pi-probe-discord-dashboard.service -n 100 --no-pager
journalctl -u pi-probe-discord-bot.service -n 100 --no-pager
```
