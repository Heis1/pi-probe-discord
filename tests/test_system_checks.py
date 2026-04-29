from __future__ import annotations

import unittest

from pi_probe_discord.system_checks import _extract_pihole_update_status


class SystemChecksTests(unittest.TestCase):
    def test_extract_pihole_update_status_detects_updates(self) -> None:
        output = """\
  [i] Core:      v6.4 (Update available!)
  [i] Web:       v6.4.1 (Update available!)
  [i] FTL:       v6.5 (Update available!)
"""
        status = _extract_pihole_update_status(output)
        self.assertIn("Update available", status)
        self.assertIn("Core", status)

    def test_extract_pihole_update_status_up_to_date(self) -> None:
        output = "  [✓] DNS service is running\n  [✓] Pi-hole blocking is enabled"
        status = _extract_pihole_update_status(output)
        self.assertEqual(status, "Up to date")


if __name__ == "__main__":
    unittest.main()
