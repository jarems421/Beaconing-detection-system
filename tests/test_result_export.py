from __future__ import annotations

import csv
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.detection import (
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    ISOLATION_FOREST_NAME,
    LOCAL_OUTLIER_FACTOR_NAME,
    LOGISTIC_REGRESSION_NAME,
    RANDOM_FOREST_NAME,
    STATISTICAL_BASELINE_NAME,
    AnomalyDetectorConfig,
    StatisticalBaselineConfig,
    SupervisedDetectorConfig,
    supervised_operating_point,
)
from beacon_detector.evaluation import (
    build_quick_evaluation_grid,
    evaluate_anomaly_detector_multi_seed,
    evaluate_rule_detector_multi_seed,
    evaluate_statistical_detector_multi_seed,
    evaluate_supervised_detector_multi_seed,
    export_experiment_tables,
    lof_candidate_name,
    lof_operating_point,
    sweep_prediction_thresholds_multi_seed,
)


class TestResultExport(unittest.TestCase):
    def test_exports_expected_result_tables(self) -> None:
        seeds = (61,)
        cases = build_quick_evaluation_grid()
        statistical_config = StatisticalBaselineConfig(benign_score_quantile=0.95)
        anomaly_config = AnomalyDetectorConfig(
            contamination=0.07,
            isolation_forest_estimators=50,
        )
        supervised_config = SupervisedDetectorConfig(
            random_forest_estimators=50,
        )
        rule_summary = evaluate_rule_detector_multi_seed(
            seeds=seeds,
            thresholds=replace(
                FROZEN_RULE_BASELINE_THRESHOLDS,
                prediction_threshold=2.8,
            ),
        )
        statistical_summary = evaluate_statistical_detector_multi_seed(
            seeds=seeds,
            config=statistical_config,
        )
        isolation_forest_summary = evaluate_anomaly_detector_multi_seed(
            "isolation_forest",
            seeds=seeds,
            config=anomaly_config,
        )
        lof_summary = evaluate_anomaly_detector_multi_seed(
            "local_outlier_factor",
            seeds=seeds,
            config=anomaly_config,
        )
        tuned_lof_config = replace(anomaly_config, lof_neighbors=35)
        tuned_lof_name = lof_candidate_name(tuned_lof_config)
        tuned_lof_summary = evaluate_anomaly_detector_multi_seed(
            "local_outlier_factor",
            seeds=seeds,
            config=tuned_lof_config,
        )
        logistic_summary = evaluate_supervised_detector_multi_seed(
            "logistic_regression",
            seeds=seeds,
            config=supervised_config,
            cases=cases[:1],
            training_seeds=(761,),
            training_cases=cases[:1],
        )
        random_forest_summary = evaluate_supervised_detector_multi_seed(
            "random_forest",
            seeds=seeds,
            config=supervised_config,
            cases=cases[:1],
            training_seeds=(761,),
            training_cases=cases[:1],
        )
        threshold_results = sweep_prediction_thresholds_multi_seed(
            thresholds_to_try=[2.2, 2.8],
            seeds=seeds,
        )

        output_dir = Path("tests/.tmp/result_export")
        output_dir.mkdir(parents=True, exist_ok=True)
        for existing_file in output_dir.glob("*"):
            if existing_file.is_file():
                existing_file.unlink()

        try:
            written_paths = export_experiment_tables(
                output_dir=output_dir,
                baseline_summaries={
                    FROZEN_RULE_BASELINE_NAME: rule_summary,
                    STATISTICAL_BASELINE_NAME: statistical_summary,
                    ISOLATION_FOREST_NAME: isolation_forest_summary,
                    LOCAL_OUTLIER_FACTOR_NAME: lof_summary,
                    tuned_lof_name: tuned_lof_summary,
                    LOGISTIC_REGRESSION_NAME: logistic_summary,
                    RANDOM_FOREST_NAME: random_forest_summary,
                },
                threshold_results=threshold_results,
                cases=cases,
                seeds=seeds,
                rule_operating_threshold=2.6,
                statistical_config=statistical_config,
                anomaly_config=anomaly_config,
                supervised_config=supervised_config,
                detector_operating_points={
                    tuned_lof_name: lof_operating_point(tuned_lof_config),
                    LOGISTIC_REGRESSION_NAME: supervised_operating_point(
                        supervised_config
                    ),
                    RANDOM_FOREST_NAME: supervised_operating_point(supervised_config),
                },
                additional_metadata={"test_context": "export_unit_test"},
            )

            expected_files = {
                "baseline_comparison.csv",
                "per_case_metrics.csv",
                "per_scenario_profile_rates.csv",
                "false_positive_summary.csv",
                "false_negative_summary.csv",
                "threshold_comparison.csv",
                "experiment_metadata.json",
            }
            self.assertEqual({path.name for path in written_paths}, expected_files)
            for file_name in expected_files:
                self.assertTrue((output_dir / file_name).exists())

            self.assert_csv_columns(
                output_dir / "baseline_comparison.csv",
                {
                    "detector_name",
                    "operating_point",
                    "mean_precision",
                    "mean_recall",
                    "mean_f1",
                    "mean_false_positive_rate",
                    "combined_tp",
                    "combined_fp",
                    "combined_tn",
                    "combined_fn",
                },
            )
            self.assert_csv_columns(
                output_dir / "per_case_metrics.csv",
                {
                    "detector_name",
                    "case_name",
                    "precision",
                    "recall",
                    "f1",
                    "false_positive_rate",
                    "tp",
                    "fp",
                    "tn",
                    "fn",
                },
            )
            self.assert_csv_columns(
                output_dir / "per_scenario_profile_rates.csv",
                {
                    "detector_name",
                    "scenario_or_profile_name",
                    "category",
                    "rate_type",
                    "rate",
                },
            )
            self.assert_csv_columns(
                output_dir / "false_positive_summary.csv",
                {
                    "detector_name",
                    "case_name",
                    "scenario_name",
                    "score",
                    "predicted_label",
                    "true_label",
                    "triggered_reasons",
                    "top_contributors",
                    "top_standardized_feature_deviations",
                },
            )
            self.assert_csv_columns(
                output_dir / "threshold_comparison.csv",
                {
                    "threshold",
                    "detector_name",
                    "mean_precision",
                    "mean_recall",
                    "mean_f1",
                    "mean_false_positive_rate",
                },
            )

            metadata = json.loads(
                (output_dir / "experiment_metadata.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["seed_list"], [61])
            self.assertIn("hardened_grid_case_names", metadata)
            self.assertIn(FROZEN_RULE_BASELINE_NAME, metadata["detector_names"])
            self.assertIn(STATISTICAL_BASELINE_NAME, metadata["detector_names"])
            self.assertIn(ISOLATION_FOREST_NAME, metadata["detector_names"])
            self.assertIn(LOCAL_OUTLIER_FACTOR_NAME, metadata["detector_names"])
            self.assertIn(tuned_lof_name, metadata["detector_names"])
            self.assertIn(LOGISTIC_REGRESSION_NAME, metadata["detector_names"])
            self.assertIn(RANDOM_FOREST_NAME, metadata["detector_names"])
            self.assertIn("statistical_baseline", metadata)
            self.assertIn("anomaly_detection", metadata)
            self.assertIn("supervised_detection", metadata)
            self.assertIn(tuned_lof_name, metadata["anomaly_detection"]["detector_names"])
            self.assertIn(
                LOGISTIC_REGRESSION_NAME,
                metadata["supervised_detection"]["detector_names"],
            )
            self.assertEqual(
                metadata["operating_points"][FROZEN_RULE_BASELINE_NAME],
                "threshold=2.6",
            )
            self.assertEqual(
                metadata["operating_points"][STATISTICAL_BASELINE_NAME],
                "benign_score_quantile=0.95",
            )
            self.assertEqual(
                metadata["operating_points"][ISOLATION_FOREST_NAME],
                "contamination=0.07",
            )
            self.assertEqual(
                metadata["operating_points"][tuned_lof_name],
                "lof_neighbors=35;contamination=0.07",
            )
            self.assertEqual(
                metadata["operating_points"][LOGISTIC_REGRESSION_NAME],
                supervised_operating_point(supervised_config),
            )
            self.assertEqual(
                metadata["additional_metadata"]["test_context"],
                "export_unit_test",
            )
        finally:
            for existing_file in output_dir.glob("*"):
                if existing_file.is_file():
                    existing_file.unlink()

    def assert_csv_columns(self, path: Path, expected_columns: set[str]) -> None:
        with path.open(newline="", encoding="utf-8") as input_file:
            reader = csv.DictReader(input_file)
            self.assertTrue(expected_columns.issubset(set(reader.fieldnames or [])))


if __name__ == "__main__":
    unittest.main()
