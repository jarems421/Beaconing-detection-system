from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import NormalTrafficProfile, SyntheticTrafficConfig
from beacon_detector.evaluation import (
    FROZEN_BASELINE_SEEDS,
    OPERATING_POINT_THRESHOLDS,
    QUICK_EVALUATION_CASE_NAMES,
    QUICK_EVALUATION_SEEDS,
    EvaluationCase,
    build_default_evaluation_grid,
    build_multiseed_evaluation_grid,
    build_quick_evaluation_grid,
    calculate_classification_metrics,
    evaluate_anomaly_detector,
    evaluate_anomaly_detector_multi_seed,
    evaluate_rule_detector,
    evaluate_rule_detector_multi_seed,
    evaluate_statistical_detector,
    evaluate_statistical_detector_multi_seed,
    evaluate_supervised_detector,
    evaluate_supervised_detector_multi_seed,
    score_distribution,
    sweep_prediction_thresholds,
    sweep_prediction_thresholds_multi_seed,
    top_false_negatives,
    top_false_positives,
)
from beacon_detector.evaluation.run import _print_detector_comparison


class TestEvaluation(unittest.TestCase):
    def test_calculates_binary_classification_metrics(self) -> None:
        metrics = calculate_classification_metrics(
            true_labels=["beacon", "beacon", "benign", "benign"],
            predicted_labels=["beacon", "benign", "beacon", "benign"],
        )

        self.assertEqual(metrics.confusion_matrix.true_positive, 1)
        self.assertEqual(metrics.confusion_matrix.false_positive, 1)
        self.assertEqual(metrics.confusion_matrix.true_negative, 1)
        self.assertEqual(metrics.confusion_matrix.false_negative, 1)
        self.assertEqual(metrics.precision, 0.5)
        self.assertEqual(metrics.recall, 0.5)
        self.assertEqual(metrics.f1_score, 0.5)
        self.assertEqual(metrics.false_positive_rate, 0.5)

    def test_default_grid_contains_multiple_stress_cases(self) -> None:
        grid = build_default_evaluation_grid(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        self.assertGreaterEqual(len(grid), 6)
        self.assertTrue(any("jitter" in case.name for case in grid))
        self.assertTrue(any("bursty" in case.name for case in grid))
        self.assertTrue(any("imbalance" in case.name for case in grid))
        case_names = {case.name for case in grid}
        self.assertIn("benign_periodic_polling", case_names)
        self.assertIn("benign_jittered_polling", case_names)
        self.assertIn("benign_burst_sleep", case_names)
        self.assertIn("benign_stable_size_repetition", case_names)
        self.assertIn("hard_class_imbalance", case_names)
        grid_profiles = {
            profile
            for case in grid
            for profile in case.config.normal_profiles
        }
        for profile in NormalTrafficProfile:
            self.assertIn(profile, grid_profiles)

    def test_evaluates_multiple_cases_in_one_run(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        base = SyntheticTrafficConfig(
            start_time=start_time,
            seed=33,
            normal_event_count=30,
            normal_flow_count=6,
            beacon_event_count=6,
        )
        cases = [
            EvaluationCase("small_base", "Small baseline case.", base),
            EvaluationCase(
                "small_high_jitter",
                "Small high-jitter case.",
                replace(base, seed=34, jitter_fraction=0.9),
            ),
        ]

        summary = evaluate_rule_detector(cases)

        self.assertGreater(len(summary.records), 0)
        self.assertEqual(
            {record.case_name for record in summary.records},
            {"small_base", "small_high_jitter"},
        )
        self.assertGreater(len(summary.per_scenario_rates), 0)
        self.assertEqual(
            {case_metric.case_name for case_metric in summary.per_case_metrics},
            {"small_base", "small_high_jitter"},
        )
        self.assertGreaterEqual(summary.overall_metrics.precision, 0.0)
        self.assertLessEqual(summary.overall_metrics.precision, 1.0)

    def test_multi_seed_evaluation_reports_metric_spread(self) -> None:
        summary = evaluate_rule_detector_multi_seed(seeds=[40, 41])

        self.assertEqual(len(summary.seed_summaries), 2)
        self.assertGreater(len(summary.combined_summary.records), 0)
        self.assertGreater(len(summary.combined_summary.per_case_metrics), 0)
        self.assertGreater(len(summary.combined_summary.per_scenario_rates), 0)
        self.assertGreaterEqual(summary.metric_spread.mean_precision, 0.0)
        self.assertLessEqual(summary.metric_spread.mean_precision, 1.0)

    def test_statistical_evaluation_runs_on_existing_pipeline(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        case = EvaluationCase(
            "small_base",
            "Small baseline case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=45,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )

        summary = evaluate_statistical_detector(
            cases=[case],
            reference_seed=46,
            start_time=start_time,
        )

        self.assertGreater(len(summary.records), 0)
        self.assertGreaterEqual(summary.overall_metrics.precision, 0.0)
        self.assertLessEqual(summary.overall_metrics.precision, 1.0)

    def test_statistical_multi_seed_evaluation_runs_cleanly(self) -> None:
        summary = evaluate_statistical_detector_multi_seed(seeds=[47, 48])

        self.assertEqual(len(summary.seed_summaries), 2)
        self.assertGreater(len(summary.combined_summary.records), 0)
        self.assertGreaterEqual(summary.metric_spread.mean_f1_score, 0.0)

    def test_anomaly_evaluation_runs_on_existing_pipeline(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        case = EvaluationCase(
            "small_base",
            "Small baseline case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=49,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )

        summary = evaluate_anomaly_detector(
            "isolation_forest",
            cases=[case],
            reference_seed=50,
            start_time=start_time,
        )

        self.assertGreater(len(summary.records), 0)
        self.assertGreaterEqual(summary.overall_metrics.precision, 0.0)
        self.assertLessEqual(summary.overall_metrics.precision, 1.0)

    def test_anomaly_multi_seed_evaluation_runs_cleanly(self) -> None:
        summary = evaluate_anomaly_detector_multi_seed(
            "local_outlier_factor",
            seeds=[51, 52],
        )

        self.assertEqual(len(summary.seed_summaries), 2)
        self.assertGreater(len(summary.combined_summary.records), 0)

    def test_supervised_evaluation_runs_on_existing_pipeline(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        case = EvaluationCase(
            "small_base",
            "Small baseline case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=54,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )
        training_case = EvaluationCase(
            "small_train",
            "Small training case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=154,
                normal_event_count=50,
                normal_flow_count=8,
                beacon_event_count=8,
            ),
        )

        summary = evaluate_supervised_detector(
            "logistic_regression",
            cases=[case],
            training_cases=[training_case],
            training_seeds=[155],
        )

        self.assertGreater(len(summary.records), 0)
        self.assertGreaterEqual(summary.overall_metrics.precision, 0.0)
        self.assertLessEqual(summary.overall_metrics.precision, 1.0)

    def test_supervised_multi_seed_evaluation_runs_cleanly(self) -> None:
        summary = evaluate_supervised_detector_multi_seed(
            "random_forest",
            seeds=[55],
            training_seeds=[755],
            cases=[build_quick_evaluation_grid()[0]],
            training_cases=[build_quick_evaluation_grid()[0]],
        )

        self.assertEqual(len(summary.seed_summaries), 1)
        self.assertGreater(len(summary.combined_summary.records), 0)

    def test_frozen_multiseed_defaults_are_explicit(self) -> None:
        self.assertEqual(FROZEN_BASELINE_SEEDS, (300, 301, 302, 303, 304))
        self.assertEqual(QUICK_EVALUATION_SEEDS, (300,))
        self.assertEqual(OPERATING_POINT_THRESHOLDS, (2.2, 2.8))

    def test_quick_evaluation_grid_is_explicit_subset(self) -> None:
        quick_grid = build_quick_evaluation_grid()

        self.assertEqual(
            {case.name for case in quick_grid},
            set(QUICK_EVALUATION_CASE_NAMES),
        )
        self.assertLess(len(quick_grid), len(build_default_evaluation_grid()))

    def test_multiseed_grid_uses_requested_seed_values(self) -> None:
        grids = build_multiseed_evaluation_grid(seeds=[50, 51])

        self.assertEqual({case.config.seed for case in grids[0]}, {50})
        self.assertEqual({case.config.seed for case in grids[1]}, {51})

    def test_threshold_sweep_returns_one_summary_per_threshold(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        case = EvaluationCase(
            "small_base",
            "Small baseline case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=42,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )

        sweep = sweep_prediction_thresholds([1.8, 2.2, 2.6], cases=[case])

        self.assertEqual([result.prediction_threshold for result in sweep], [1.8, 2.2, 2.6])
        self.assertTrue(all(len(result.summary.records) > 0 for result in sweep))

    def test_multiseed_threshold_sweep_returns_combined_summaries(self) -> None:
        sweep = sweep_prediction_thresholds_multi_seed(
            [2.2, 2.8],
            seeds=[52, 53],
            cases=build_quick_evaluation_grid(),
        )

        self.assertEqual([result.prediction_threshold for result in sweep], [2.2, 2.8])
        self.assertTrue(
            all(len(result.summary.combined_summary.records) > 0 for result in sweep)
        )

    def test_diagnostics_helpers_return_inspectable_outputs(self) -> None:
        start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        case = EvaluationCase(
            "small_base",
            "Small baseline case.",
            SyntheticTrafficConfig(
                start_time=start_time,
                seed=35,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )
        summary = evaluate_rule_detector([case])

        self.assertIsInstance(top_false_positives(summary), list)
        self.assertIsInstance(top_false_negatives(summary), list)
        self.assertIsInstance(score_distribution(summary.records, bucket_size=0.5), dict)

    def test_detector_comparison_output_is_compact(self) -> None:
        case = build_quick_evaluation_grid()[0]
        summary = evaluate_rule_detector_multi_seed(seeds=[53], cases=[case])

        import contextlib
        from io import StringIO

        output = StringIO()
        with contextlib.redirect_stdout(output):
            _print_detector_comparison({"test_detector": summary})

        text = output.getvalue()
        self.assertIn("Detector Comparison", text)
        self.assertIn("detector_name,precision,recall,f1,false_positive_rate", text)
        self.assertIn("test_detector", text)


if __name__ == "__main__":
    unittest.main()
