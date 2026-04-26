#!/usr/bin/env python3

import sys

from pi_probe_discord.installer import run_install


if __name__ == "__main__":
    raise SystemExit(run_install(sys.argv[1:]))
