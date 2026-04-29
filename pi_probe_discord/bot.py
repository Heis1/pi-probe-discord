from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass

import discord
from discord import app_commands

START_SPEEDTEST_COMMAND = [
    "sudo",
    "/bin/systemctl",
    "start",
    "--no-block",
    "pi-probe-discord-speedtest.service",
]
START_FULLREPORT_COMMAND = [
    "sudo",
    "/bin/systemctl",
    "start",
    "--no-block",
    "pi-probe-discord-full.service",
]

UNAUTHORISED_MESSAGE = "You are not authorised to run this command."
STARTED_MESSAGE = "Speed test started. Results will post shortly."
FULLREPORT_STARTED_MESSAGE = "Full report started. Results will post shortly."


@dataclass
class BotConfig:
    token: str
    allowed_user_ids: set[int]
    command_guild_id: int | None = None
    log_level: str = "INFO"


def load_bot_config() -> BotConfig:
    token = os.environ.get("PI_PROBE_DISCORD_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("PI_PROBE_DISCORD_BOT_TOKEN is not set.")

    raw_ids = os.environ.get("PI_PROBE_DISCORD_ALLOWED_USER_IDS", "").strip()
    if not raw_ids:
        raise RuntimeError("PI_PROBE_DISCORD_ALLOWED_USER_IDS is not set.")

    allowed_user_ids: set[int] = set()
    for raw_id in raw_ids.split(","):
        candidate = raw_id.strip()
        if not candidate:
            continue
        if not candidate.isdigit():
            raise RuntimeError(f"Invalid Discord user ID: {candidate}")
        allowed_user_ids.add(int(candidate))

    if not allowed_user_ids:
        raise RuntimeError("No valid PI_PROBE_DISCORD_ALLOWED_USER_IDS were configured.")

    raw_guild_id = os.environ.get("PI_PROBE_DISCORD_COMMAND_GUILD_ID", "").strip()
    command_guild_id = int(raw_guild_id) if raw_guild_id.isdigit() else None

    return BotConfig(
        token=token,
        allowed_user_ids=allowed_user_ids,
        command_guild_id=command_guild_id,
        log_level=os.environ.get("PI_PROBE_DISCORD_BOT_LOG_LEVEL", "INFO").strip() or "INFO",
    )


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


class PiProbeDiscordBot(discord.Client):
    def __init__(self, config: BotConfig) -> None:
        super().__init__(intents=discord.Intents.none())
        self.config = config
        self.logger = logging.getLogger("pi_probe_discord.bot")
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        @self.tree.command(name="speedtest", description="Trigger a Pi speed test.")
        async def speedtest(interaction: discord.Interaction) -> None:
            await self.handle_service_start(interaction, START_SPEEDTEST_COMMAND, STARTED_MESSAGE, "speedtest")

        @self.tree.command(name="fullreport", description="Trigger a full Pi report.")
        async def fullreport(interaction: discord.Interaction) -> None:
            await self.handle_service_start(interaction, START_FULLREPORT_COMMAND, FULLREPORT_STARTED_MESSAGE, "fullreport")

        if self.config.command_guild_id is not None:
            guild = discord.Object(id=self.config.command_guild_id)
            self.tree.clear_commands(guild=None)
            await self.tree.sync()
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            self.logger.info("Synced /speedtest and /fullreport to guild %s", self.config.command_guild_id)
        else:
            await self.tree.sync()
            self.logger.info("Synced /speedtest and /fullreport globally")

    async def on_ready(self) -> None:
        self.logger.info("Discord bot connected as %s (%s)", self.user, getattr(self.user, "id", "unknown"))

    async def handle_service_start(
        self,
        interaction: discord.Interaction,
        start_command: list[str],
        started_message: str,
        command_name: str,
    ) -> None:
        user = interaction.user
        username = f"{user} ({user.id})"

        if user.id not in self.config.allowed_user_ids:
            self.logger.warning("Unauthorized /%s attempt by %s", command_name, username)
            await interaction.response.send_message(UNAUTHORISED_MESSAGE, ephemeral=True)
            return

        self.logger.info("Authorized /%s request by %s", command_name, username)

        try:
            subprocess.run(
                start_command,
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except subprocess.CalledProcessError as exc:
            self.logger.error(
                "Failed to start service for /%s by %s: returncode=%s stderr=%s",
                command_name,
                username,
                exc.returncode,
                exc.stderr.strip(),
            )
            await interaction.response.send_message(
                "Command could not be started right now.",
                ephemeral=True,
            )
            return
        except subprocess.TimeoutExpired:
            self.logger.error("Timed out starting service for /%s by %s", command_name, username)
            await interaction.response.send_message(
                "Command could not be started right now.",
                ephemeral=True,
            )
            return

        await interaction.response.send_message(started_message)


def main() -> int:
    config = load_bot_config()
    configure_logging(config.log_level)
    bot = PiProbeDiscordBot(config)
    bot.run(config.token, log_handler=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
