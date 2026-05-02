# pi-probe-discord

`pi-probe-discord` is a Raspberry Pi monitoring and Discord reporting app for a Pi-hole box or home network node.

It does three jobs:

- runs scheduled internet speed checks
- reports Pi-hole and update status to Discord
- stores local history in SQLite so charts and reports are based on the Pi's own data

The project is packaged as a Debian `.deb`, can run headless over SSH, and is built to be maintained without editing one giant script.

## What It Reports

- download, upload, and ping
- chart image for recent history
- verdict based on recent local baseline, not fixed generic thresholds
- Pi-hole service state
- Pi-hole blocking enabled or disabled
- gravity age and blocklist size when available
- apt update and upgrade summary
- UFW firewall snapshot and recent blocked traffic summary

## Discord Bot

The repo also includes a small Discord slash-command bot for one narrow job:

- `/speedtest`
- `/fullreport`
- `/firewall`
- only for configured Discord user IDs
- starts fixed systemd units only:
  - `pi-probe-discord-speedtest.service`
  - `pi-probe-discord-full.service`
  - fixed `ufw status verbose` and log reads for firewall snapshot

It does not run arbitrary shell commands.

## Project Layout

- `pihole_update_report.py`
  Thin CLI entrypoint.
- `pi_probe_discord/`
  Application package.
- `install.py`
  Interactive installer for Pi setup and schedule configuration.
- `scripts/release.sh`
  Build, tag, and publish a GitHub release with the `.deb`.
- `scripts/update-from-release.sh`
  Source copy of the Pi-side upgrade helper.
- `pi-probe-discord-update`
  Installed system command for upgrading from a local or released `.deb`.
- `pihole_speedtest_bot.py`
  Discord slash-command bot entrypoint.
- `pi-probe-discord-bot.service`
  Example systemd unit for running the bot at boot.
- `pi-probe-discord-bot.env.example`
  Bot token and allowed user ID template.
- `pi-probe-discord-bot.sudoers.example`
  Narrow sudoers example for the bot.
- `debian/`
  Debian packaging files.
- `DEPLOYMENT.md`
  Pi installation and upgrade guide.

## How It Runs

The app is split into modes so frequent speed tests do not also run system maintenance:

```bash
python3 pihole_update_report.py speedtest-only
python3 pihole_update_report.py full
python3 pihole_update_report.py update-only
python3 pihole_update_report.py report 7
python3 pihole_update_report.py firewall
```

Normal deployment uses `systemd` timers:

- `pi-probe-discord-speedtest.timer`
- `pi-probe-discord-full.timer`

## Data Storage

Runs are stored in SQLite.

- default DB path: `/var/lib/pi-probe-discord/pi_probe_discord.db`
- default retention: 12 months
- old rows are pruned automatically

This history drives the Discord chart and the health verdict logic.

## Configuration

The webhook is not committed in the repo.

Expected installed config path:

```text
/etc/pi-probe-discord/pihole-update-discord.env
```

Example template:

```bash
cp pihole-update-discord.env.example pihole-update-discord.env
chmod 600 pihole-update-discord.env
```

The installer can also create this file for you.

## Install On A Pi

Use the full guide in [DEPLOYMENT.md](DEPLOYMENT.md).

Short version:

1. Copy the repo to the Pi.
2. Install Python and dependencies.
3. Run `python3 install.py`.
4. Install the `.deb` or copy the app into `/opt/pi-probe-discord`.
5. Enable the timers.

Everything can be done over SSH. No Pi desktop session is required.

## Discord Bot Setup

Create the bot config file:

```bash
sudo cp /usr/share/pi-probe-discord/pi-probe-discord-bot.env.example /etc/pi-probe-discord/pi-probe-discord-bot.env
sudo chmod 600 /etc/pi-probe-discord/pi-probe-discord-bot.env
```

Set:

- `PI_PROBE_DISCORD_BOT_TOKEN`
- `PI_PROBE_DISCORD_ALLOWED_USER_IDS`

Optional:

- `PI_PROBE_DISCORD_COMMAND_GUILD_ID`
  Use this while testing so slash-command sync is fast.

Install the narrow sudoers rule:

```bash
sudo visudo -f /etc/sudoers.d/pi-probe-discord-bot
```

Add exactly:

```text
aron ALL=(root) NOPASSWD: /bin/systemctl start --no-block pi-probe-discord-speedtest.service
aron ALL=(root) NOPASSWD: /bin/systemctl start pi-probe-discord-speedtest.service
aron ALL=(root) NOPASSWD: /bin/systemctl start --no-block pi-probe-discord-full.service
aron ALL=(root) NOPASSWD: /bin/systemctl start pi-probe-discord-full.service
aron ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
# Optional if logs are only in journald:
aron ALL=(root) NOPASSWD: /usr/bin/journalctl -k --since -24 hours --no-pager
```

Then enable the bot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pi-probe-discord-bot.service
```

Check logs:

```bash
journalctl -u pi-probe-discord-bot.service -n 100 --no-pager
```

## Firewall Reporting

Enable UFW logging:

```bash
sudo ufw logging on
```

Check status:

```bash
sudo ufw status verbose
```

Run a manual firewall snapshot:

```bash
pi-probe-discord-firewall --window-hours 24
pi-probe-discord-firewall --json
```

Relevant config keys in `pihole-update-discord.env`:

- `PI_PROBE_FIREWALL_ENABLED=true`
- `PI_PROBE_FIREWALL_WINDOW_HOURS=24`
- `PI_PROBE_FIREWALL_TOP_N=5`
- `PI_PROBE_FIREWALL_NOISY_SOURCE_THRESHOLD=10`
- `PI_PROBE_FIREWALL_INCLUDE_ALLOW=false`
- `PI_PROBE_FIREWALL_LOG_PATHS=/var/log/ufw.log,/var/log/kern.log,/var/log/syslog`
- `PI_PROBE_FIREWALL_ALERT_ENABLED=true`
- `PI_PROBE_FIREWALL_ALERT_MIN_BLOCKS=80`
- `PI_PROBE_FIREWALL_ALERT_MIN_SSH_ATTEMPTS=20`
- `PI_PROBE_FIREWALL_ALERT_MIN_NOISY_SOURCES=2`
- `PI_PROBE_FIREWALL_ALERT_COOLDOWN_MINUTES=60`
- `PI_PROBE_FIREWALL_ALERT_STATE_FILE=/var/lib/pi-probe-discord/firewall_alert_state.json`

If no entries are found, this does not necessarily mean UFW is broken. Logging may be disabled, quiet, permission-limited, or handled by journald.

When firewall alerting is enabled, `full` runs will post a separate red "Firewall Attack Alert" embed if one or more thresholds are exceeded. Cooldown suppresses repeated alerts for the configured number of minutes.

## Build The Debian Package

```bash
sudo apt-get install -y debhelper
dpkg-buildpackage -us -uc -b
```

That produces a package like:

```text
../pi-probe-discord_0.1.0-1_all.deb
```

## Install Or Upgrade On The Pi

If you already have the `.deb` on the Pi:

```bash
sudo apt install /home/aron/pi-probe-discord_0.1.0-1_all.deb
sudo systemctl daemon-reload
sudo systemctl restart pi-probe-discord-speedtest.timer pi-probe-discord-full.timer
```

If schedule or installer-managed config needs to be refreshed:

```bash
sudo pi-probe-discord-install
```

## Release Workflow

Create a release from the development machine with:

```bash
scripts/release.sh "Improve Discord chart readability"
```

That script:

- derives the next patch version from `debian/changelog` by default
- updates `debian/changelog`
- commits the release metadata
- creates the matching git tag
- builds the `.deb`
- creates a GitHub release
- uploads the `.deb` asset

If you need a specific version instead of the automatic patch bump:

```bash
scripts/release.sh --version 0.2.0 "Add Pi upgrade helper"
```

## Pi Upgrade Helper

On the Pi, the packaged upgrade helper can install from:

- a local `.deb` path
- a direct release URL
- a release version like `0.1.1`
- `latest`

Examples:

```bash
sudo pi-probe-discord-update /home/aron/pi-probe-discord_0.1.1-1_all.deb
sudo pi-probe-discord-update 0.1.1
sudo pi-probe-discord-update latest
```

If the GitHub repo is private, the Pi needs either:

- authenticated `gh`, or
- `GITHUB_TOKEN` exported in the shell

If you also want to rerun installer-based config after upgrading:

```bash
sudo pi-probe-discord-update latest --reconfigure
```

## Notes

- The app still posts a Discord embed if chart generation is unavailable.
- `matplotlib` is required for the image chart.
- Pi-hole details degrade gracefully if Pi-hole commands are unavailable.
- The repo also includes `pihole-update-discord.sh`, a simpler shell-only reporter for update/Pi-hole reporting.

## Architecture

- `pi_probe_discord/config.py`
  config loading and validation
- `pi_probe_discord/storage.py`
  SQLite persistence and retention
- `pi_probe_discord/system_checks.py`
  apt and Pi-hole collection
- `pi_probe_discord/speedtest_runner.py`
  speed test execution
- `pi_probe_discord/status.py`
  baseline-aware health verdict logic
- `pi_probe_discord/charts.py`
  Discord chart rendering
- `pi_probe_discord/discord_client.py`
  embed/file posting
- `pi_probe_discord/installer.py`
  interactive setup and timer overrides
- `pi_probe_discord/app.py`
  orchestration
