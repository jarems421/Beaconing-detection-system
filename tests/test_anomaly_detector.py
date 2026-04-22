from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    GenerationScenario,
    SyntheticTrafficConfig,
    generate_synthetic_events,
)
from beacon_detector.detection import (
    AnomalyDetectorConfig,
    AnomalyDetectorModel,
    detect_flow_feature_rows_anomaly,
    fit_anomaly_detector,
    score_flow_features_anomaly,
)
from beacon_detector.features import extract_features_from_flows
from beacon_detector.flows import build_flows


class TestAnomalyDetector(unittest.TestCase):
    def test_isolation_forest_fit_score_predict_flow(self) -> None:
        reference_features = _features_for_scenario(GenerationScenario.NORMAL, seed=81)
        model = fit_anomaly_detector(
            reference_features,
            detector_type="isolation_forest",
            config=AnomalyDetectorConfig(isolation_forest_estimators=50),
        )

        score, contributions = score_flow_features_anomaly(reference_features[0], model)

        self.assertEqual(model.detector_name, "isolation_forest_v1")
        self.assertLess(model.reference_flow_count, len(reference_features))
        self.assertGreater(model.calibration_flow_count, 0)
        self.assertEqual(
            model.reference_flow_count + model.calibration_flow_count,
            len(reference_features),
        )
        self.assertIsInstance(score, float)
        self.assertGreater(len(contributions), 0)

    def test_local_outlier_factor_fit_score_predict_flow(self) -> None:
        reference_features = _features_for_scenario(GenerationScenario.NORMAL, seed=82)
        model = fit_anomaly_detector(
            reference_features,
            detector_type="local_outlier_factor",
            config=AnomalyDetectorConfig(lof_neighbors=5),
        )
        fixed_features = _features_for_scenario(GenerationScenario.FIXED, seed=83)

        results = detect_flow_feature_rows_anomaly(fixed_features, model=model)

        self.assertEqual(model.detector_name, "local_outlier_factor_v1")
        self.assertGreater(model.calibration_flow_count, 0)
        self.assertGreater(len(results), 0)
        self.assertTrue(
            all(result.predicted_label in {"benign", "beacon"} for result in results)
        )
        self.assertTrue(all(len(result.contributions) > 0 for result in results))

    def test_scores_rows_in_one_estimator_call(self) -> None:
        reference_features = _features_for_scenario(GenerationScenario.NORMAL, seed=85)
        model = fit_anomaly_detector(
            reference_features,
            detector_type="local_outlier_factor",
            config=AnomalyDetectorConfig(lof_neighbors=5),
        )
        counting_estimator = CountingEstimator(model.estimator)
        counting_model: AnomalyDetectorModel = replace(
            model,
            estimator=counting_estimator,
        )

        detect_flow_feature_rows_anomaly(reference_features[:5], model=counting_model)

        self.assertEqual(counting_estimator.call_count, 1)

    def test_requires_benign_reference_rows(self) -> None:
        beacon_features = [
            row for row in _features_for_scenario(GenerationScenario.FIXED, seed=84)
            if row.label == "beacon"
        ]

        with self.assertRaises(ValueError):
            fit_anomaly_detector(beacon_features, detector_type="isolation_forest")


def _features_for_scenario(
    scenario: GenerationScenario,
    seed: int,
):
    config = SyntheticTrafficConfig(
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        seed=seed,
        normal_event_count=80,
        normal_flow_count=12,
        beacon_event_count=12,
    )
    return extract_features_from_flows(
        build_flows(generate_synthetic_events(config, scenario))
    )


class CountingEstimator:
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.call_count = 0

    def decision_function(self, rows):
        self.call_count += 1
        return self.wrapped.decision_function(rows)


if __name__ == "__main__":
    unittest.main()
