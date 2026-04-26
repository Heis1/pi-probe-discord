# Raspberry Pi Deployment

This guide installs `pi-probe-discord` onto a Raspberry Pi and enables automatic Discord reporting.

## What This Installs

- the Python application under `/opt/pi-probe-discord`
- a local virtual environment
- Python dependencies from `requirements.txt`
- an interactive config file with your Discord webhook
- `systemd` timers for periodic speed tests and daily full reports

## 1. Copy The Project To The Pi

From your main computer:

```bash
scp -r pi-probe-discord pi@your-pi:/home/pi/
```

Or clone it directly on the Pi if the repo is hosted remotely.

## 2. SSH Into The Pi

```bash
ssh pi@your-pi
cd /home/pi/pi-probe-discord
```

## 3. Install System Packages

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
```

If your Pi does not already have Pi-hole tools installed, the app will still run, but the Pi-hole fields will show warnings.

## 4. Create A Virtual Environment

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Run The Interactive Installer

```bash
python3 install.py
```

It will ask for:

- Discord webhook URL
- speedtest publish frequency in minutes
- daily full report time in `HH:MM`

It also checks for:

- overlapping cron jobs in the current user crontab
- related `systemd` units and timers that may need disabling

It will generate:

- `pihole-update-discord.env`
- `generated-systemd/pi-probe-discord-speedtest.service`
- `generated-systemd/pi-probe-discord-speedtest.timer`
- `generated-systemd/pi-probe-discord-full.service`
- `generated-systemd/pi-probe-discord-full.timer`

If matching cron jobs are found, the installer can remove them from the current user's crontab before you enable the new timers.
The generated webhook config file is written with `600` permissions.
The installer also validates the webhook URL before writing the config.

## 6. Install The App Into `/opt`

```bash
sudo mkdir -p /opt/pi-probe-discord
sudo mkdir -p /etc/pi-probe-discord
sudo mkdir -p /var/lib/pi-probe-discord
sudo rsync -a --delete /home/pi/pi-probe-discord/ /opt/pi-probe-discord/
sudo chown -R root:root /opt/pi-probe-discord
```

## 7. Install Python Dependencies Into The App Venv

```bash
cd /opt/pi-probe-discord
sudo python3 -m venv .venv
sudo /opt/pi-probe-discord/.venv/bin/pip install --upgrade pip
sudo /opt/pi-probe-discord/.venv/bin/pip install -r /opt/pi-probe-discord/requirements.txt
```

## 8. Install The Generated Config

```bash
sudo cp pihole-update-discord.env /etc/pi-probe-discord/pihole-update-discord.env
sudo chown root:root /etc/pi-probe-discord/pihole-update-discord.env
sudo chmod 600 /etc/pi-probe-discord/pihole-update-discord.env
```

## 9. Install The Generated systemd Units

```bash
sudo cp generated-systemd/*.service /etc/systemd/system/
sudo cp generated-systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pi-probe-discord-speedtest.timer
sudo systemctl enable --now pi-probe-discord-full.timer
```

The generated service files already point at:

```text
/opt/pi-probe-discord/.venv/bin/python
```

The app now defaults to:

```text
config: /etc/pi-probe-discord/pihole-update-discord.env
data:   /var/lib/pi-probe-discord/
```

## 10. Smoke Test The App

Run a one-off speed test report:

```bash
sudo /opt/pi-probe-discord/.venv/bin/python /opt/pi-probe-discord/pihole_update_report.py speedtest-only
```

Run a full report:

```bash
sudo /opt/pi-probe-discord/.venv/bin/python /opt/pi-probe-discord/pihole_update_report.py full
```

Check the timers:

```bash
systemctl list-timers --all | grep pi-probe-discord
```

## 11. Useful Maintenance Commands

Inspect timer logs:

```bash
journalctl -u pi-probe-discord-speedtest.service -n 100 --no-pager
journalctl -u pi-probe-discord-full.service -n 100 --no-pager
```

Generate a local report from the database:

```bash
sudo /opt/pi-probe-discord/.venv/bin/python /opt/pi-probe-discord/pihole_update_report.py report 7
```

## Notes

- The database keeps up to 12 months of data by default.
- The chart is built from SQLite history and posted to Discord when `matplotlib` is installed.
- If `matplotlib` is missing, the app still posts an embed without the image.
- If the speedtest Python package is missing, the app records and reports that failure rather than crashing.
- If you install via `.deb`, rerun `sudo pi-probe-discord-install` whenever you want to change publish frequency or daily report time. It updates `systemd` timer override files instead of requiring package reinstall.

## Upgrade From A New Release

When a new `.deb` is published from GitHub:

```bash
scp pi-probe-discord_<version>-1_all.deb aron@raspberrypi:/home/aron/
ssh aron@raspberrypi
sudo apt install /home/aron/pi-probe-discord_<version>-1_all.deb
sudo systemctl daemon-reload
sudo systemctl restart pi-probe-discord-speedtest.timer pi-probe-discord-full.timer
```

Or use the repo helper directly on the Pi:

```bash
sudo scripts/update-from-release.sh /home/aron/pi-probe-discord_<version>-1_all.deb
sudo scripts/update-from-release.sh latest
```

If the GitHub repo is private, `latest` and version-based downloads require either authenticated `gh` on the Pi or `GITHUB_TOKEN` in the shell.

If the release changed schedule/config behavior, rerun:

```bash
sudo pi-probe-discord-install
```
