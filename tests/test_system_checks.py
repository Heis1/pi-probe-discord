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

    def test_extract_pihole_update_status_from_latest_format(self) -> None:
        output = """\
Core version is v6.4 (Latest: v6.4.2)
Web version is v6.4.1 (Latest: v6.5)
FTL version is v6.5 (Latest: v6.6.1)
"""
        status = _extract_pihole_update_status(output)
        self.assertIn("Core v6.4->v6.4.2", status)
        self.assertIn("Web v6.4.1->v6.5", status)
        self.assertIn("FTL v6.5->v6.6.1", status)


if __name__ == "__main__":
    unittest.main()
