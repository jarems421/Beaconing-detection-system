from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig, generate_combined_synthetic_dataset
from beacon_detector.detection import (
    LOGISTIC_REGRESSION_NAME,
    RANDOM_FOREST_NAME,
    SupervisedDetectorConfig,
    detect_flow_feature_rows_supervised,
    fit_supervised_detector,
)
from beacon_detector.features import extract_features_from_flows
from beacon_detector.flows import build_flows


class TestSupervisedDetector(unittest.TestCase):
    def test_logistic_regression_fit_predict_flow(self) -> None:
        training_rows = _training_features(seed=81)
        model = fit_supervised_detector(
            training_rows,
            detector_type="logistic_regression",
            config=SupervisedDetectorConfig(logistic_max_iter=500),
        )

        results = detect_flow_feature_rows_supervised(training_rows[:5], model=model)

        self.assertEqual(model.detector_name, LOGISTIC_REGRESSION_NAME)
        self.assertGreater(model.beacon_training_flow_count, 0)
        self.assertGreater(model.benign_training_flow_count, 0)
        self.assertEqual(len(results), 5)
        self.assertTrue(
            all(result.predicted_label in {"benign", "beacon"} for result in results)
        )
        self.assertTrue(all(0.0 <= result.score <= 1.0 for result in results))
        self.assertTrue(all(len(result.contributions) > 0 for result in results))

    def test_random_forest_fit_predict_flow(self) -> None:
        training_rows = _training_features(seed=82)
        model = fit_supervised_detector(
            training_rows,
            detector_type="random_forest",
            config=SupervisedDetectorConfig(random_forest_estimators=50),
        )

        results = detect_flow_feature_rows_supervised(training_rows[:5], model=model)

        self.assertEqual(model.detector_name, RANDOM_FOREST_NAME)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(0.0 <= result.score <= 1.0 for result in results))

    def test_requires_both_labels(self) -> None:
        benign_only = [row for row in _training_features(seed=83) if row.label == "benign"]

        with self.assertRaises(ValueError):
            fit_supervised_detector(benign_only, detector_type="logistic_regression")


def _training_features(seed: int):
    config = SyntheticTrafficConfig(
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        seed=seed,
        normal_event_count=80,
        normal_flow_count=12,
        beacon_event_count=12,
    )
    return extract_features_from_flows(
        build_flows(generate_combined_synthetic_dataset(config))
    )


if __name__ == "__main__":
    unittest.main()
