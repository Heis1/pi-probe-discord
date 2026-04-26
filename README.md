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
  Pi-side upgrade helper for installing a local or released `.deb`.
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

On the Pi, the upgrade helper can install from:

- a local `.deb` path
- a direct release URL
- a release version like `0.1.1`
- `latest`

Examples:

```bash
sudo scripts/update-from-release.sh /home/aron/pi-probe-discord_0.1.1-1_all.deb
sudo scripts/update-from-release.sh 0.1.1
sudo scripts/update-from-release.sh latest
```

If the GitHub repo is private, the Pi needs either:

- authenticated `gh`, or
- `GITHUB_TOKEN` exported in the shell

If you also want to rerun installer-based config after upgrading:

```bash
sudo scripts/update-from-release.sh latest --reconfigure
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
