from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    SyntheticTrafficConfig,
    TrafficEvent,
    generate_combined_synthetic_dataset,
    save_events_to_csv,
)
from beacon_detector.features import (
    calculate_adaptive_bin_summary,
    calculate_adjacent_similarity_fraction,
    calculate_dominant_interval_fraction,
    calculate_interarrival_times,
    calculate_longest_similar_run,
    calculate_median_absolute_percentage_deviation,
    calculate_near_median_fraction,
    calculate_range_median_ratio,
    calculate_trimmed_cv,
    detect_bursts,
    extract_features_from_flow,
    extract_features_from_flows,
)
from beacon_detector.flows import Flow, build_flows, load_flows_from_csv


class TestFeatureExtraction(unittest.TestCase):
    def test_calculates_interarrival_times(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flow = Flow.from_events(
            [
                _event(start),
                _event(start + timedelta(seconds=10)),
                _event(start + timedelta(seconds=30)),
            ]
        )

        features = extract_features_from_flow(flow)

        self.assertEqual(calculate_interarrival_times(flow), [10.0, 20.0])
        self.assertEqual(features.mean_interarrival_seconds, 15.0)
        self.assertEqual(features.median_interarrival_seconds, 15.0)
        self.assertEqual(features.std_interarrival_seconds, 5.0)
        self.assertEqual(features.min_interarrival_seconds, 10.0)
        self.assertEqual(features.max_interarrival_seconds, 20.0)
        self.assertEqual(features.interarrival_iqr_seconds, 10.0)
        self.assertEqual(features.interarrival_mad_seconds, 5.0)
        self.assertIsNotNone(features.trimmed_interarrival_cv)
        self.assertEqual(features.near_median_interarrival_fraction, 0.0)
        self.assertEqual(features.interarrival_within_10pct_median_fraction, 0.0)
        self.assertEqual(features.interarrival_within_20pct_median_fraction, 0.0)
        self.assertEqual(features.interarrival_within_30pct_median_fraction, 0.0)
        self.assertEqual(features.dominant_interval_fraction, 0.5)
        self.assertEqual(features.interval_bin_count, 2)
        self.assertEqual(features.adjacent_gap_similarity_fraction, 0.0)
        self.assertEqual(features.longest_similar_gap_run, 1)
        self.assertAlmostEqual(features.gap_range_median_ratio or 0.0, 10.0 / 15.0)

    def test_calculates_timing_consistency_helpers(self) -> None:
        values = [60.0, 62.0, 59.0, 61.0, 240.0]

        self.assertLess(calculate_trimmed_cv(values) or 1.0, 0.75)
        self.assertEqual(calculate_near_median_fraction(values), 0.8)
        self.assertEqual(calculate_dominant_interval_fraction(values), 0.8)
        self.assertEqual(calculate_adjacent_similarity_fraction(values), 0.75)
        self.assertEqual(calculate_longest_similar_run(values), 4)
        self.assertAlmostEqual(
            calculate_range_median_ratio(values) or 0.0,
            (240.0 - 59.0) / 61.0,
        )
        self.assertLess(
            calculate_median_absolute_percentage_deviation(values) or 1.0,
            0.04,
        )

    def test_calculates_adaptive_bin_summary(self) -> None:
        summary = calculate_adaptive_bin_summary([60.0, 61.0, 63.0, 180.0])

        self.assertEqual(summary.bin_count, 2)
        self.assertEqual(summary.dominant_bin_fraction, 0.75)

    def test_handles_one_event_flow(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flow = Flow.from_events([_event(start, size_bytes=250)])

        features = extract_features_from_flow(flow)

        self.assertEqual(features.event_count, 1)
        self.assertEqual(features.total_bytes, 250)
        self.assertEqual(features.flow_duration_seconds, 0.0)
        self.assertIsNone(features.mean_interarrival_seconds)
        self.assertIsNone(features.interarrival_within_10pct_median_fraction)
        self.assertIsNone(features.adjacent_gap_similarity_fraction)
        self.assertIsNone(features.longest_similar_gap_run)
        self.assertIsNone(features.gap_range_median_ratio)
        self.assertIsNone(features.events_per_second)
        self.assertEqual(features.mean_size_bytes, 250.0)
        self.assertEqual(features.std_size_bytes, 0.0)
        self.assertEqual(features.size_cv, 0.0)
        self.assertEqual(features.normalized_size_range, 0.0)
        self.assertEqual(features.near_median_size_fraction, 1.0)
        self.assertEqual(features.burst_count, 0)
        self.assertIsNone(features.avg_burst_size)

    def test_handles_two_event_flow_gap_features_without_crashing(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flow = Flow.from_events(
            [
                _event(start, size_bytes=120),
                _event(start + timedelta(seconds=55), size_bytes=140),
            ]
        )

        features = extract_features_from_flow(flow)

        self.assertEqual(features.event_count, 2)
        self.assertEqual(features.interarrival_within_10pct_median_fraction, 1.0)
        self.assertIsNone(features.adjacent_gap_similarity_fraction)
        self.assertEqual(features.longest_similar_gap_run, 1)
        self.assertEqual(features.gap_range_median_ratio, 0.0)

    def test_detects_bursts_from_interarrival_threshold(self) -> None:
        summary = detect_bursts(
            interarrival_times_seconds=[1.0, 2.0, 30.0, 1.0],
            burst_threshold_seconds=5.0,
        )

        self.assertEqual(summary.burst_sizes, (3, 2))
        self.assertEqual(summary.sleep_durations_seconds, (30.0,))
        self.assertEqual(summary.within_burst_gaps_seconds, (1.0, 2.0, 1.0))
        self.assertEqual(summary.total_burst_duration_seconds, 4.0)
        self.assertEqual(summary.total_sleep_duration_seconds, 30.0)

    def test_extracts_burst_features(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flow = Flow.from_events(
            [
                _event(start),
                _event(start + timedelta(seconds=1)),
                _event(start + timedelta(seconds=3)),
                _event(start + timedelta(seconds=33)),
                _event(start + timedelta(seconds=34)),
            ]
        )

        features = extract_features_from_flow(flow, burst_threshold_seconds=5.0)

        self.assertEqual(features.burst_count, 2)
        self.assertEqual(features.avg_burst_size, 2.5)
        self.assertEqual(features.max_burst_size, 3)
        self.assertEqual(features.burst_size_variance, 0.25)
        self.assertAlmostEqual(features.burst_size_cv or 0.0, 0.2)
        self.assertEqual(features.avg_sleep_duration_seconds, 30.0)
        self.assertAlmostEqual(features.within_burst_gap_consistency or 0.0, 2.0 / 3.0)
        self.assertAlmostEqual(features.burst_to_idle_ratio or 0.0, 4.0 / 30.0)

    def test_rejects_mixed_label_flows_by_default(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flow = build_flows(
            [
                _event(start, label="benign"),
                _event(start + timedelta(seconds=5), label="beacon"),
            ]
        )[0]

        with self.assertRaises(ValueError):
            extract_features_from_flow(flow)

    def test_extracts_features_from_sample_csv_derived_flows(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=18,
            normal_event_count=12,
            beacon_event_count=6,
        )
        events = generate_combined_synthetic_dataset(config)
        csv_path = Path("tests/.tmp/feature_events.csv")
        try:
            save_events_to_csv(events, csv_path)
            flows = load_flows_from_csv(csv_path)
            feature_rows = extract_features_from_flows(flows)
        finally:
            if csv_path.exists():
                csv_path.unlink()

        self.assertEqual(len(feature_rows), len(flows))
        self.assertTrue(any(row.label == "beacon" for row in feature_rows))
        self.assertTrue(any(row.label == "benign" for row in feature_rows))


def _event(
    timestamp: datetime,
    size_bytes: int = 100,
    label: str = "beacon",
) -> TrafficEvent:
    return TrafficEvent(
        timestamp=timestamp,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="tcp",
        size_bytes=size_bytes,
        label=label,  # type: ignore[arg-type]
        scenario_name="fixed_periodic",
    )


if __name__ == "__main__":
    unittest.main()
