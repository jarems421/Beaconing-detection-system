from __future__ import annotations

import sys
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    GenerationScenario,
    NormalTrafficProfile,
    SyntheticTrafficConfig,
    generate_combined_synthetic_dataset,
    generate_synthetic_events,
    save_events_to_csv,
)
from beacon_detector.detection import (
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    HIGH_PRECISION_RULE_BASELINE_THRESHOLDS,
    detect_flow_feature_rows,
    detect_flow_features,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import FlowKey, build_flows, load_flows_from_csv


class TestRuleDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=17,
            normal_event_count=30,
            beacon_event_count=8,
            mean_interval_seconds=45.0,
            jitter_fraction=0.30,
            sleep_duration_seconds=180.0,
            burst_size_min=2,
            burst_size_max=4,
        )

    def test_normal_flow_distribution_is_not_trivially_sparse(self) -> None:
        flows = build_flows(generate_combined_synthetic_dataset(self.config))
        normal_counts = [
            flow.event_count
            for flow in flows
            if flow.label == "benign"
            and len(flow.scenario_names) == 1
            and flow.scenario_names[0].startswith("normal_")
        ]
        distribution = Counter(normal_counts)

        self.assertEqual(distribution[1], 0)
        self.assertEqual(distribution[2], 0)
        self.assertGreaterEqual(sum(1 for count in normal_counts if count >= 3), 1)
        self.assertGreaterEqual(sum(1 for count in normal_counts if count >= 5), 1)

    def test_rule_baseline_configs_are_named_and_frozen(self) -> None:
        self.assertEqual(FROZEN_RULE_BASELINE_NAME, "rule_baseline_v2_hardened_final")
        self.assertEqual(FROZEN_RULE_BASELINE_THRESHOLDS.prediction_threshold, 2.2)
        self.assertEqual(FROZEN_RULE_BASELINE_THRESHOLDS.constant_size_cv_threshold, 0.02)
        self.assertEqual(
            HIGH_PRECISION_RULE_BASELINE_THRESHOLDS.prediction_threshold,
            2.8,
        )
        self.assertEqual(
            HIGH_PRECISION_RULE_BASELINE_THRESHOLDS.periodic_cv_threshold,
            FROZEN_RULE_BASELINE_THRESHOLDS.periodic_cv_threshold,
        )

    def test_adversarial_benign_profiles_have_multi_event_flows(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=44,
            normal_event_count=48,
            normal_flow_count=len(NormalTrafficProfile),
        )
        flows = build_flows(generate_synthetic_events(config, GenerationScenario.NORMAL))

        profile_to_counts = {
            flow.scenario_names[0]: flow.event_count
            for flow in flows
            if flow.scenario_names and flow.scenario_names[0].startswith("normal_")
        }

        for profile in NormalTrafficProfile:
            self.assertIn(profile.value, profile_to_counts)
            self.assertGreaterEqual(profile_to_counts[profile.value], 3)

    def test_benign_bursty_session_contains_burst_sleep_structure(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=47,
            normal_event_count=36,
            normal_flow_count=4,
            normal_events_per_flow_min=6,
            normal_events_per_flow_max=12,
            normal_profiles=(NormalTrafficProfile.BURSTY_SESSION,),
        )
        flows = build_flows(generate_synthetic_events(config, GenerationScenario.NORMAL))
        features = extract_features_from_flows(flows)

        self.assertTrue(
            any(
                row.scenario_name == NormalTrafficProfile.BURSTY_SESSION.value
                and (row.burst_count or 0) > 0
                and row.avg_sleep_duration_seconds is not None
                for row in features
            )
        )

    def test_fixed_beaconing_is_flagged(self) -> None:
        result = _detect_scenario(self.config, GenerationScenario.FIXED)

        self.assertEqual(result.predicted_label, "beacon")
        self.assertIn("low_interarrival_variability", _triggered_rule_names(result))

    def test_jittered_beaconing_is_flagged(self) -> None:
        result = _detect_scenario(self.config, GenerationScenario.JITTERED)

        self.assertEqual(result.predicted_label, "beacon")
        self.assertGreaterEqual(result.score, result.threshold)

    def test_bursty_beaconing_uses_burst_aware_logic(self) -> None:
        result = _detect_scenario(self.config, GenerationScenario.BURSTY)

        self.assertEqual(result.predicted_label, "beacon")
        self.assertIn("burst_sleep_structure", _triggered_rule_names(result))

    def test_improved_normal_flows_are_not_all_flagged(self) -> None:
        flows = build_flows(generate_combined_synthetic_dataset(self.config))
        features = extract_features_from_flows(flows)
        normal_results = [
            detect_flow_features(row)
            for row in features
            if row.label == "benign"
            and row.scenario_name is not None
            and row.scenario_name.startswith("normal_")
        ]

        false_positives = [
            result for result in normal_results if result.predicted_label == "beacon"
        ]
        self.assertLess(len(false_positives), len(normal_results))

    def test_detector_output_includes_reason_contributions(self) -> None:
        result = _detect_scenario(self.config, GenerationScenario.FIXED)

        self.assertGreater(len(result.contributions), 0)
        self.assertGreater(len(result.triggered_reasons), 0)

    def test_short_regular_benign_like_flow_stays_below_threshold(self) -> None:
        result = detect_flow_features(
            _feature_row(
                label="benign",
                event_count=6,
                flow_duration_seconds=420.0,
                mean_interarrival_seconds=84.0,
                inter_arrival_cv=0.25,
                interarrival_iqr_seconds=35.0,
                size_cv=0.18,
            )
        )

        self.assertEqual(result.predicted_label, "benign")

    def test_long_jittered_repetition_can_be_flagged_without_low_cv(self) -> None:
        result = detect_flow_features(
            _feature_row(
                label="beacon",
                event_count=18,
                flow_duration_seconds=960.0,
                mean_interarrival_seconds=56.0,
                inter_arrival_cv=0.47,
                interarrival_iqr_seconds=50.0,
                size_cv=0.40,
            )
        )

        self.assertEqual(result.predicted_label, "beacon")
        self.assertIn("long_low_rate_repetition", _triggered_rule_names(result))

    def test_weak_two_burst_pattern_is_not_enough_by_itself(self) -> None:
        result = detect_flow_features(
            _feature_row(
                label="benign",
                event_count=8,
                flow_duration_seconds=230.0,
                mean_interarrival_seconds=33.0,
                inter_arrival_cv=1.4,
                interarrival_iqr_seconds=63.0,
                size_cv=0.44,
                burst_count=2,
                avg_burst_size=3.5,
                avg_sleep_duration_seconds=100.0,
                burst_to_idle_ratio=0.12,
            )
        )

        self.assertEqual(result.predicted_label, "benign")

    def test_sample_csv_derived_features_can_be_scored_end_to_end(self) -> None:
        events = generate_combined_synthetic_dataset(self.config)
        csv_path = Path("tests/.tmp/rule_detector_events.csv")
        try:
            save_events_to_csv(events, csv_path)
            flows = load_flows_from_csv(csv_path)
            features = extract_features_from_flows(flows)
            results = detect_flow_feature_rows(features)
        finally:
            if csv_path.exists():
                csv_path.unlink()

        beacon_results = [result for result in results if result.true_label == "beacon"]
        self.assertEqual(len(beacon_results), 4)
        predicted_beacon_scenarios = {
            result.scenario_name
            for result in beacon_results
            if result.predicted_label == "beacon"
        }
        self.assertIn("fixed_periodic", predicted_beacon_scenarios)
        self.assertIn("jittered", predicted_beacon_scenarios)
        self.assertIn("bursty", predicted_beacon_scenarios)


def _detect_scenario(config: SyntheticTrafficConfig, scenario: GenerationScenario):
    flows = build_flows(generate_synthetic_events(config, scenario))
    features = extract_features_from_flows(flows)
    scenario_features = next(row for row in features if row.scenario_name == scenario.value)
    return detect_flow_features(scenario_features)


def _triggered_rule_names(result) -> set[str]:
    return {
        contribution.rule_name
        for contribution in result.contributions
        if contribution.fired and contribution.score > 0
    }


def _feature_row(
    *,
    label: str,
    event_count: int,
    flow_duration_seconds: float,
    mean_interarrival_seconds: float,
    inter_arrival_cv: float,
    interarrival_iqr_seconds: float,
    size_cv: float,
    burst_count: int = 0,
    avg_burst_size: float | None = None,
    avg_sleep_duration_seconds: float | None = None,
    burst_to_idle_ratio: float | None = None,
) -> FlowFeatures:
    return FlowFeatures(
        flow_key=FlowKey(
            src_ip="10.0.0.1",
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="tcp",
        ),
        label=label,  # type: ignore[arg-type]
        scenario_name="test",
        event_count=event_count,
        total_bytes=event_count * 100,
        flow_duration_seconds=flow_duration_seconds,
        mean_interarrival_seconds=mean_interarrival_seconds,
        median_interarrival_seconds=mean_interarrival_seconds,
        std_interarrival_seconds=mean_interarrival_seconds * inter_arrival_cv,
        min_interarrival_seconds=mean_interarrival_seconds,
        max_interarrival_seconds=mean_interarrival_seconds,
        interarrival_iqr_seconds=interarrival_iqr_seconds,
        interarrival_mad_seconds=interarrival_iqr_seconds / 2,
        inter_arrival_cv=inter_arrival_cv,
        events_per_second=event_count / flow_duration_seconds,
        events_per_minute=(event_count / flow_duration_seconds) * 60,
        burst_count=burst_count,
        avg_burst_size=avg_burst_size,
        max_burst_size=int(avg_burst_size) if avg_burst_size is not None else None,
        burst_size_variance=0.0 if avg_burst_size is not None else None,
        avg_sleep_duration_seconds=avg_sleep_duration_seconds,
        sleep_duration_variance=0.0 if avg_sleep_duration_seconds is not None else None,
        burst_to_idle_ratio=burst_to_idle_ratio,
        mean_size_bytes=100.0,
        median_size_bytes=100.0,
        std_size_bytes=100.0 * size_cv,
        size_cv=size_cv,
    )


if __name__ == "__main__":
    unittest.main()
