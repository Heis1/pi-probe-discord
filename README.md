# pi-probe-discord

`pi-probe-discord` is a Pi-hosted home-network monitor. It runs reliable internet checks, watches core network devices, stores local history in SQLite, and posts concise results to Discord.

## This deployment

This repository is tailored for the deployed home network rather than being a generic monitoring template. It monitors the Pi-hosted services, Pi-hole and internet performance, a FortiWiFi 30E at `10.10.10.1`, and a FortiAP-U431F at `10.10.10.105`. The interactive dashboard combines live keep-alive checks, FortiWiFi API health, and inventory across both `192.168.1.0/24` and `10.10.10.0/24`.

HTTPS is backed by the local **Pi Probe Local CA**. Its private key remains root-only on the Pi; clients trust its CA certificate instead. Your deployment settings live in `/etc/pi-probe-discord/pihole-update-discord.env`, while secrets such as the FortiWiFi API token remain in separate protected files.

### Preserve local customisation

Normal package upgrades preserve the configuration file and data directory. Do not use `--reconfigure` casually: it launches the interactive installer. When an existing configuration is detected, the installer now requires explicit confirmation and creates a timestamped `pihole-update-discord.env.backup-YYYYMMDD-HHMMSS` file before replacing it.

## What it does

- scheduled or on-demand internet speed tests using the native Ookla CLI
- Discord delivery through either a webhook or a configured bot channel
- concise speed alerts with current result, time-matched baseline, and next action
- interactive dashboard that leads with the latest result and offers a `Run speed test` action
- live router/access-point keep-alive checks and normalised core-network health
- optional router SMTP log ingest, remote syslog, firewall, Pi-hole, SNMP, Nmap, and update reporting

## Version 1.2 highlights

- **Trustworthy speed tests:** the probe prefers the native Ookla client over the legacy Python `speedtest-cli` implementation. This avoids unreliable readings on high-speed links and records the selected test server.
- **Live network health:** routers and access points can be monitored independently every minute. The dashboard shows a compact green `Normal` state only when live checks and current inventory agree.
- **Actionable dashboard:** latest download, upload, and ping are shown first. Speed, ping, and DNS activity are separate views; historical router noise is not presented as a current fault.
- **Discord that lands in the right place:** scheduled reports post directly to the configured bot channel, without competing with the long-running Discord bot gateway connection.

Use the native Ookla CLI on a Raspberry Pi 64-bit installation:

```bash
curl -fL -o /tmp/ookla-speedtest.tgz https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz
tar -xzf /tmp/ookla-speedtest.tgz -C /tmp
sudo install -m 0755 /tmp/speedtest /usr/local/bin/ookla-speedtest
/usr/local/bin/ookla-speedtest --accept-license --accept-gdpr
```

## Quick start

Install or upgrade:

```bash
sudo pi-probe-discord-update latest
```

Edit config:

```bash
sudo nano /etc/pi-probe-discord/pihole-update-discord.env
```

Configure one Discord delivery method:

```bash
WEBHOOK_URL="https://discord.com/api/webhooks/replace/this"
```

Or configure `PI_PROBE_DISCORD_BOT_TOKEN` and `PI_PROBE_DISCORD_REPORT_CHANNEL_ID` in `/etc/pi-probe-discord/pi-probe-discord-bot.env`.

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
pi-probe-discord fortigate
pi-probe-discord network-diagnose
pi-probe-discord dashboard-html
pi-probe-discord dashboard-serve
pi-probe-discord dashboard-check
pi-probe-discord doctor
```

Speed tests are intentionally rate-limited to at least 30 minutes. If an old installer-created timer override is causing minute-by-minute runs, stop it immediately and remove the override before re-enabling the timer:

```bash
sudo systemctl disable --now pi-probe-discord-speedtest.timer
sudo rm -rf /etc/systemd/system/pi-probe-discord-speedtest.timer.d
sudo systemctl daemon-reload
```

The packaged timer runs its first test ten minutes after activation, then schedules the next one an hour after each completed test. This avoids overlapping or runaway one-shot tests.

## Dashboard setup

The interactive dashboard is the day-to-day view of the connection. It is designed to answer three questions quickly:

1. **What did the latest test measure?** The top row shows the most recent download, upload, and ping result first. The 30-day median and averages beneath each value are context, not the headline.
2. **Is the network normal right now?** `Core Network Health` is green and says `Normal` only when the monitored router/access point keep-alives are reachable and the inventory is current. Historical router events do not keep a fault active after recovery.
3. **What should I do next?** The connection panel explains the current state and provides a `Run speed test` button when an immediate measurement is needed.

### Dashboard panels

- **Connection status:** latest result, target attainment, recent failures, and an on-demand speed-test action.
- **Router Keep-Alive:** independent minute-by-minute reachability for configured routers and access points, including latency.
- **Core Network Health:** live infrastructure-only diagnosis. Phones and other client devices are excluded from fault classification.
- **Speed Over Time / Ping Over Time:** separate views of throughput and latency. Router events are kept in their own recent-events panel rather than being overlaid on the charts.
- **DNS Activity:** Pi-hole request and blocked-request volume for operational context. It does not claim DNS traffic caused a speed change.
- **Network Devices and Security Signal:** inventory, device categorisation, and only actionable external/security activity. Historical LAN broadcast noise is de-emphasised.

### Run a test now

Open the dashboard and select `Run speed test`. The browser starts the packaged one-shot service and refreshes after the test completes. If `PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN` is set, enter that token in the dashboard before using actions.

From the Pi CLI, the equivalent command is:

```bash
sudo pi-probe-discord speedtest-only
```

The dashboard uses the native Ookla client when installed, so start a new baseline after switching from the legacy Python client. Do not compare old `speedtest-cli` history directly with new Ookla measurements.

### Enable and access it

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
- `/api/dashboard/data`

`/api/dashboard/data` is read-only and returns the same dashboard data already visible in the page. The browser polls it every `PI_PROBE_DASHBOARD_REFRESH_SECONDS` seconds, with a hard minimum of 15 seconds, pauses while the tab is hidden, and refreshes immediately when the tab becomes visible again.

Recommended refresh and action settings:

```bash
PI_PROBE_DASHBOARD_REFRESH_SECONDS="60"
PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN=""
```

If you set `PI_PROBE_INTERACTIVE_DASHBOARD_API_TOKEN`, the token is required for dashboard actions such as manual Nmap scans and saved device overrides. Read-only dashboard polling does not use the token and does not trigger a new Nmap scan.

## Nmap inventory and Bambu Lab identification

The LAN inventory pipeline stores raw Nmap XML plus a JSON inventory at:

- `/var/lib/pi-probe-discord/nmap/latest.xml`
- `/var/lib/pi-probe-discord/nmap/latest.json`
- `/var/lib/pi-probe-discord/nmap/events.json`
- `/var/lib/pi-probe-discord/nmap/overrides.json`

The inventory now fingerprints Bambu Lab printers from scan evidence. A confirmed match requires Bambu certificate evidence such as `BBL Technologies Co. Ltd`, `BBL Device CA`, `BBL CA`, or certificate text containing `Printer`. Supporting evidence includes FTPS on TCP `990`, `vsftpd 3.0.5`, and the Bambu service-port pattern on TCP `3000` and `6000`.

Confirmed devices appear in the dashboard as `Bambu Lab 3D Printer` with:

- printer styling
- IP address
- `Device ID` when the certificate CN is already visible in scan data
- identification confidence
- concise verification evidence

Port `3000` alone is never treated as proof of a Bambu device.

Recommended Nmap settings:

```bash
PI_PROBE_NMAP_SCAN_MINUTES="360"
```

The scheduled scan uses the packaged `pi-probe-discord-nmap.service` and `pi-probe-discord-nmap.timer`. Package upgrades preserve the configured interval by regenerating the timer override from `PI_PROBE_NMAP_SCAN_MINUTES`, with a floor of 5 minutes.

Inspect the Nmap timer and recent scans:

```bash
sudo systemctl status pi-probe-discord-nmap.timer --no-pager
sudo systemctl list-timers pi-probe-discord-nmap.timer --all
sudo systemctl cat pi-probe-discord-nmap.timer
sudo journalctl -u pi-probe-discord-nmap.service -n 50 --no-pager
```

Run a manual inventory scan:

```bash
sudo pi-probe-discord nmap-scan
```

The interactive dashboard can also start a manual scan when an action token is configured. After a successful scan, the browser fetches fresh dashboard JSON immediately instead of waiting for the next polling interval.

## Automated topology and visual diagram

The dashboard can now build an automated LAN topology view from SNMP bridge MAC tables instead of relying on guessed uplinks.

What it does:

- walks bridge forwarding tables from configured infrastructure nodes
- matches learned client MAC addresses to scanned inventory devices
- identifies downstream devices behind extenders or access points
- derives parent links for infrastructure nodes when their MAC addresses appear in another node's FDB
- renders a visual topology diagram in the live dashboard

Install the SNMP tools on the Pi:

```bash
sudo apt install snmp
```

Example topology configuration:

```bash
PI_PROBE_TOPOLOGY_ENABLED="true"
PI_PROBE_TOPOLOGY_NODES_JSON='[
  {"id":"router","name":"Main Router","host":"192.168.1.1","management_ip":"192.168.1.1","community":"public","role":"router"},
  {"id":"access-point","name":"Access Point","host":"192.168.1.2","management_ip":"192.168.1.2","community":"public","role":"access_point"}
]'
PI_PROBE_TOPOLOGY_CACHE_JSON="/var/lib/pi-probe-discord/topology/latest.json"
PI_PROBE_TOPOLOGY_REFRESH_MINUTES="30"
PI_PROBE_TOPOLOGY_SNMPWALK_BIN="snmpwalk"
PI_PROBE_TOPOLOGY_SNMP_TIMEOUT_SECONDS="6"
```

Notes:

- this requires SNMP read access on the router, extender, switch, or access point you want to map
- the topology poll is separate from dashboard JSON polling
- dashboard refresh polling does not trigger Nmap or SNMP topology scans by itself
- topology data is cached and reused until the refresh interval expires

## Router Web UI Secrets

If you later enable router web UI scraping, keep the credentials out of the main env file.

Main config:

```bash
PI_PROBE_ROUTER_WEBUI_ENABLED="true"
PI_PROBE_ROUTER_WEBUI_URL="http://192.168.1.1"
PI_PROBE_ROUTER_WEBUI_SECRET_FILE="/etc/pi-probe-discord/router-webui.env"
PI_PROBE_ROUTER_WEBUI_CA_FILE="/etc/pi-probe-discord/router-webui-ca.pem"
```

Secret file:

```bash
sudo install -o root -g root -m 600 /usr/share/pi-probe-discord/router-webui.env.example /etc/pi-probe-discord/router-webui.env
sudo nano /etc/pi-probe-discord/router-webui.env
```

The secret file must:

- be owned by `root`
- have mode `600`
- define `PI_PROBE_ROUTER_WEBUI_USERNAME`
- define `PI_PROBE_ROUTER_WEBUI_PASSWORD`

The dashboard payload and normal status views do not expose these values.

To avoid trusting arbitrary certificates on the LAN, export or copy the router's current HTTPS certificate to:

```bash
/etc/pi-probe-discord/router-webui-ca.pem
```

When `PI_PROBE_ROUTER_WEBUI_CA_FILE` points to that file, Pi Probe pins the router connection to that exact certificate before logging in.

## FortiWiFi 30E reporting

Pi Probe can poll a FortiWiFi/FortiGate through its read-only FortiOS Monitor API and place gateway identity, CPU, memory, and active-session reporting on the dashboard. It sends only `GET` requests; the API token stays in a root-only file and is never put in dashboard JSON.

Set the gateway, access-point, and FortiAP reachability checks in `/etc/pi-probe-discord/pihole-update-discord.env`:

```bash
PI_PROBE_KEEPALIVE_ENABLED="true"
PI_PROBE_KEEPALIVE_DEVICES_JSON='[{"name":"Upstairs Router","host":"192.168.1.1","role":"router"},{"name":"FortiWiFi 30E","host":"10.10.10.1","role":"firewall"},{"name":"AX20 Downstairs","host":"10.10.10.2","role":"access_point"},{"name":"FortiAP-U431F","host":"10.10.10.105","role":"access_point"}]'
PI_PROBE_FORTIGATE_ENABLED="true"
FORTIGATE_BASE_URL="https://10.10.10.1"
PI_PROBE_FORTIGATE_VDOM="root"
PI_PROBE_FORTIGATE_CA_FILE="/etc/pi-probe-discord/fortigate-ca.pem"
```

Replace `10.10.10.1` with the FortiWiFi management address if it differs. Create a least-privilege REST API administrator on the FortiWiFi, restrict its trusted hosts to the Pi's IP, then install its token without adding it to the main configuration:

```bash
sudo install -o root -g root -m 600 /usr/share/pi-probe-discord/fortigate.env.example /etc/pi-probe-discord/fortigate.env
sudo nano /etc/pi-probe-discord/fortigate.env
sudo install -o root -g pi-probe-discord -m 640 /path/to/fortigate-ca.pem /etc/pi-probe-discord/fortigate-ca.pem
sudo systemctl enable --now pi-probe-discord-fortigate.timer pi-probe-discord-keepalive.timer
sudo pi-probe-discord fortigate
```

To include devices behind the FortiWiFi in the inventory and dashboard, add its routed subnet to the Nmap targets. Targets are space-separated:

```bash
PI_PROBE_NMAP_TARGETS="192.168.1.0/24 10.10.10.0/24"
```

For a Pi upstream of the FortiWiFi, configure its host route and the narrow FortiGate `wan -> internal` policy outside this application. The program never changes Linux routes or FortiGate firewall rules. A one-shot `pi-probe-discord fortigate` result identifies the precise failing stage (`route`, `tcp`, `tls`, `authentication`, `http`, `api`, or `parsing`) without logging the API token.

The collector uses FortiOS monitor endpoints for system status and one-minute CPU, memory, and session values. Fortinet documents the monitor resource endpoint and API-token workflow in its [FortiOS monitoring reference](https://docs.fortinet.com/document/fortigate/7.4.6/fortinet-carrier-grade-nat-field-reference-architecture-guide/725722/rest-api-for-monitoring).

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
- set the trap destination host to the Pi's LAN address, for example `192.168.1.50`
- set the trap destination UDP port to `162`
- trigger a test trap or a real link event, then rerun `sudo pi-probe-discord router`

## Important files

- config: `/etc/pi-probe-discord/pihole-update-discord.env`
- bot config: `/etc/pi-probe-discord/pi-probe-discord-bot.env`
- data: `/var/lib/pi-probe-discord/pi_probe_discord.db`
- chart image: `/var/lib/pi-probe-discord/speed_chart.png`
- dashboard HTML: `/var/lib/pi-probe-discord/dashboard/index.html`
- dashboard status: `/var/lib/pi-probe-discord/dashboard/status.json`
- Nmap XML: `/var/lib/pi-probe-discord/nmap/latest.xml`
- Nmap inventory JSON: `/var/lib/pi-probe-discord/nmap/latest.json`
- Nmap scan state JSON: `/var/lib/pi-probe-discord/nmap/state.json`

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
