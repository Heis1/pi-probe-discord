from __future__ import annotations

from datetime import datetime, timedelta
import unittest

from pi_probe_discord.baselines import calculate_same_time_baseline
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
        self.assertAlmostEqual(stats.same_time_avg or 0.0, 45.0, places=2)
        self.assertEqual(stats.same_time_samples, 2)

    def test_comparison_text_download_degraded(self) -> None:
        text, _ = _comparison_text("download", latest=30.0, baseline=50.0)
        self.assertIn("Degraded", text)

    def test_comparison_text_ping_elevated(self) -> None:
        text, _ = _comparison_text("ping", latest=24.0, baseline=20.0)
        self.assertIn("Elevated", text)

    def test_comparison_text_not_enough_data(self) -> None:
        text, _ = _comparison_text("upload", latest=None, baseline=10.0)
        self.assertEqual(text, "Not enough data")

    def test_same_time_baseline_uses_prior_days_only(self) -> None:
        now = datetime(2026, 4, 29, 21, 0, 0)
        points = [
            (now - timedelta(days=3, minutes=10), 310.0),
            (now - timedelta(days=2, minutes=5), 290.0),
            (now - timedelta(days=1, minutes=20), 300.0),
            (now - timedelta(hours=1), 450.0),
        ]
        baseline = calculate_same_time_baseline(points, now)
        self.assertEqual(baseline.sample_count, 3)
        self.assertAlmostEqual(baseline.avg or 0.0, 300.0, places=2)
        self.assertEqual(baseline.low, 290.0)
        self.assertEqual(baseline.high, 310.0)

    def test_calculate_metric_stats_populates_same_time_average(self) -> None:
        now = datetime(2026, 4, 29, 21, 0, 0)
        points = [
            (now - timedelta(days=3, minutes=10), 310.0),
            (now - timedelta(days=2, minutes=5), 290.0),
            (now - timedelta(days=1, minutes=20), 300.0),
            (now - timedelta(minutes=15), 255.0),
        ]
        stats = calculate_metric_stats(points, now)
        self.assertEqual(stats.latest, 255.0)
        self.assertAlmostEqual(stats.same_time_avg or 0.0, 300.0, places=2)
        self.assertEqual(stats.same_time_samples, 3)


if __name__ == "__main__":
    unittest.main()
