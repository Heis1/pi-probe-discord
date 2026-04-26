# pi-probe-discord

Small Raspberry Pi / Pi-hole Discord reporting application.

This repo contains:

- `pihole_update_report.py`
  Thin CLI entry point for the application.
- `install.py`
  Interactive Pi setup helper that asks for the Discord webhook and publish frequency.
- `pi_probe_discord/`
  Modular application package with config, storage, Discord, chart, installer, and probe logic split into maintainable modules.
- `pihole-update-discord.sh`
  Simpler shell version for apt update + Pi-hole reporting only.
- `pihole-update-discord.env.example`
  Example config file for the Discord webhook URL.
- `pi-probe-discord-speedtest.service` and `.timer`
  Default example `systemd` units.
- `pi-probe-discord-full.service` and `.timer`
  Default example `systemd` units for a daily full run.
- `samples/`
  Mock Discord payload and chart output examples for previewing the final result.
- `requirements.txt`
  Python dependencies for the full application.
- `DEPLOYMENT.md`
  Step-by-step Raspberry Pi install guide.
- `debian/`
  Debian packaging files for building a `.deb`.

## Features

- Discord webhook config kept out of committed code
- apt update and upgrade summary
- Pi-hole service status
- Pi-hole blocking enabled or disabled state
- gravity database age
- blocklist domain count
- speedtest results
- Discord embed formatting
- SQLite storage for historical runs
- graph upload when `matplotlib` is installed
- built-in CLI report mode for stored history
- interactive install/setup flow for Raspberry Pi deployment
- configurable publishing frequency for periodic speedtest reporting
- modular code layout intended to be modified and extended

## Setup

For a full Pi install, use `DEPLOYMENT.md`.

To build a Debian package:

```bash
sudo apt-get install -y debhelper
dpkg-buildpackage -us -uc -b
```

To install the resulting package on a Pi:

```bash
sudo dpkg -i ../pi-probe-discord_0.1.0-1_all.deb
sudo pi-probe-discord-install
```

To change the packaged timer schedule later:

```bash
sudo pi-probe-discord-install
```

That command updates the config and writes `systemd` timer override files, so you do not need to reinstall the `.deb`.

Interactive install on the Pi:

```bash
python3 install.py
```

This installer asks for:

- Discord webhook URL
- speedtest publish frequency in minutes
- daily full report time
- whether overlapping cron jobs should be removed from the current user crontab

It writes:

- `pihole-update-discord.env`
- generated `systemd` unit files under `generated-systemd/`

It also:

- scans the current user crontab for overlapping Pi-hole, speedtest, and Discord-style jobs
- shows a cleanup preview before removing matching cron entries
- scans for related `systemd` service and timer units and prints disable commands for old units
- writes the generated webhook config with `600` permissions
- validates that the webhook URL is a real Discord HTTPS webhook format

Manual config is still available. Copy the example config:

```bash
cp pihole-update-discord.env.example pihole-update-discord.env
chmod 600 pihole-update-discord.env
```

Set your real webhook URL in `pihole-update-discord.env`.
The intended installed location is `/etc/pi-probe-discord/pihole-update-discord.env`.

## Python Requirements

Install the Python dependencies on the Raspberry Pi:

```bash
python3 -m pip install -r requirements.txt
```

If you want the polished dark-mode chart, keep `matplotlib` installed.

## Stored Data

The Python reporter stores every run in a local SQLite database:

- default path: `/var/lib/pi-probe-discord/pi_probe_discord.db`
- override with `DB_PATH`
- default retention: 365 days

Each stored run includes:

- timestamp
- hostname
- apt update result and summary
- Pi-hole status fields
- speedtest result fields
- warnings and errors

This database is the source for the Discord trend graph.
Old rows are pruned automatically on each run, and the database is incrementally vacuumed to keep disk usage under control.

## Run

Combined Python reporter:

```bash
python3 pihole_update_report.py
```

Run only a periodic speed test and Discord post:

```bash
python3 pihole_update_report.py speedtest-only
```

Run only the full update and Pi-hole maintenance report:

```bash
python3 pihole_update_report.py full
```

Run only update and Pi-hole checks without a speed test:

```bash
python3 pihole_update_report.py update-only
```

Generate a local text report from the stored database:

```bash
python3 pihole_update_report.py report
python3 pihole_update_report.py report 30
```

Shell-only reporter:

```bash
bash pihole-update-discord.sh
```

## Periodic Scheduling

For a Raspberry Pi, `systemd` timers are the sensible option.

Suggested schedule:

- hourly `speedtest-only`
- daily `full`

The installer generates schedule-aware unit files for you. If you are installing manually, a typical flow is:

```bash
sudo mkdir -p /opt/pi-probe-discord
sudo mkdir -p /etc/pi-probe-discord
sudo mkdir -p /var/lib/pi-probe-discord
sudo cp -r . /opt/pi-probe-discord/
sudo cp pihole-update-discord.env /etc/pi-probe-discord/pihole-update-discord.env
sudo chmod 600 /etc/pi-probe-discord/pihole-update-discord.env
sudo cp /opt/pi-probe-discord/generated-systemd/*.service /etc/systemd/system/
sudo cp /opt/pi-probe-discord/generated-systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pi-probe-discord-speedtest.timer
sudo systemctl enable --now pi-probe-discord-full.timer
```

## Notes

- The Python script posts a graph image only when `matplotlib` is installed.
- The real chart now uses the same dark-mode visual direction as the polished sample, with highlighted problem zones.
- The Python script builds the graph from SQLite history, with both `Last 24 Hours` and `Last 7 Days` trend panels.
- By default, the database keeps at most 12 months of data and trims large stored text fields.
- The app now defaults to Debian-style paths: config in `/etc/pi-probe-discord` and data in `/var/lib/pi-probe-discord`.
- The script still posts a readable Discord embed if the graph cannot be generated.
- The real `pihole-update-discord.env` file is ignored by git.

## Architecture

The application is deliberately split so it can grow:

- `pi_probe_discord/config.py`
  runtime configuration loading
- `pi_probe_discord/storage.py`
  SQLite persistence and reporting
- `pi_probe_discord/system_checks.py`
  apt and Pi-hole collection
- `pi_probe_discord/speedtest_runner.py`
  speed test collection
- `pi_probe_discord/charts.py`
  chart generation and styling
- `pi_probe_discord/discord_client.py`
  Discord payload creation and posting
- `pi_probe_discord/installer.py`
  interactive setup and timer generation
- `pi_probe_discord/app.py`
  orchestration layer
