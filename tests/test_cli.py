from __future__ import annotations

import unittest

from pi_probe_discord.cli import parse_mode


class CliTests(unittest.TestCase):
    def test_parse_mode_dashboard_html(self) -> None:
        mode, extra = parse_mode(["pi-probe-discord", "dashboard-html"])
        self.assertEqual(mode, "dashboard-html")
        self.assertIsNone(extra)

    def test_parse_mode_dashboard_serve(self) -> None:
        mode, extra = parse_mode(["pi-probe-discord", "dashboard-serve"])
        self.assertEqual(mode, "dashboard-serve")
        self.assertIsNone(extra)


if __name__ == "__main__":
    unittest.main()
