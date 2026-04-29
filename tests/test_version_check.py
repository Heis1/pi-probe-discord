from __future__ import annotations

import unittest

from pi_probe_discord.version_check import _parse_semver


class VersionCheckTests(unittest.TestCase):
    def test_parse_semver_plain(self) -> None:
        self.assertEqual(_parse_semver("0.1.4"), (0, 1, 4))

    def test_parse_semver_with_prefix_and_suffix(self) -> None:
        self.assertEqual(_parse_semver("v0.1.4-1"), (0, 1, 4))

    def test_parse_semver_invalid(self) -> None:
        self.assertIsNone(_parse_semver("latest"))


if __name__ == "__main__":
    unittest.main()
