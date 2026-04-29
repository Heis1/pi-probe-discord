from __future__ import annotations

from datetime import datetime, timedelta
import unittest

from pi_probe_discord.charts import _comparison_text, calculate_metric_stats


class ChartStatsTests(unittest.TestCase):
    def test_calculate_metric_stats_populates_24h_and_7d(self) -> None:
        now = datetime(2026, 4, 29, 12, 0, 0)
        points = [
            (now - timedelta(days=6), 40.0),
            (now - timedelta(hours=23), 50.0),
            (now - timedelta(hours=2), 45.0),
        ]
        stats = calculate_metric_stats(points, now)
        self.assertEqual(stats.latest, 45.0)
        self.assertEqual(stats.samples_24h, 2)
        self.assertEqual(stats.samples_7d, 3)
        self.assertAlmostEqual(stats.avg_24h or 0.0, 47.5, places=2)
        self.assertAlmostEqual(stats.avg_7d or 0.0, 45.0, places=2)
        self.assertEqual(stats.min_24h, 45.0)
        self.assertEqual(stats.max_24h, 50.0)

    def test_comparison_text_download_degraded(self) -> None:
        text, _ = _comparison_text("download", latest=30.0, avg_24h=50.0)
        self.assertIn("Degraded", text)

    def test_comparison_text_ping_elevated(self) -> None:
        text, _ = _comparison_text("ping", latest=24.0, avg_24h=20.0)
        self.assertIn("Elevated", text)

    def test_comparison_text_not_enough_data(self) -> None:
        text, _ = _comparison_text("upload", latest=None, avg_24h=10.0)
        self.assertEqual(text, "Not enough data")


if __name__ == "__main__":
    unittest.main()
