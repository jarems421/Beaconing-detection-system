from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    GenerationScenario,
    SyntheticTrafficConfig,
    generate_synthetic_events,
)
from beacon_detector.detection import (
    DEFAULT_STATISTICAL_FEATURES,
    StatisticalBaselineConfig,
    detect_flow_feature_rows_statistical,
    fit_statistical_baseline,
    score_flow_features,
)
from beacon_detector.features import extract_features_from_flows
from beacon_detector.flows import build_flows


class TestStatisticalDetector(unittest.TestCase):
    def test_fits_benign_reference_and_scores_rows(self) -> None:
        reference_features = _features_for_scenario(GenerationScenario.NORMAL, seed=71)
        model = fit_statistical_baseline(reference_features)

        self.assertLess(model.reference_flow_count, len(reference_features))
        self.assertGreater(model.calibration_flow_count, 0)
        self.assertEqual(
            model.reference_flow_count + model.calibration_flow_count,
            len(reference_features),
        )
        self.assertEqual(
            tuple(reference.feature_name for reference in model.references),
            DEFAULT_STATISTICAL_FEATURES,
        )
        self.assertGreater(model.prediction_threshold, 0.0)

        score, contributions = score_flow_features(reference_features[0], model)

        self.assertGreaterEqual(score, 0.0)
        self.assertGreater(len(contributions), 0)
        self.assertTrue(all(contribution.fired for contribution in contributions))

    def test_predicts_with_structured_contributions(self) -> None:
        reference_features = _features_for_scenario(GenerationScenario.NORMAL, seed=72)
        model = fit_statistical_baseline(
            reference_features,
            config=StatisticalBaselineConfig(benign_score_quantile=0.95),
        )
        fixed_features = _features_for_scenario(GenerationScenario.FIXED, seed=73)

        results = detect_flow_feature_rows_statistical(fixed_features, model=model)

        self.assertGreater(len(results), 0)
        self.assertTrue(
            all(result.predicted_label in {"benign", "beacon"} for result in results)
        )
        self.assertTrue(all(result.score >= 0.0 for result in results))
        self.assertTrue(
            all(len(result.top_contributing_features) > 0 for result in results)
        )

    def test_requires_benign_reference_rows(self) -> None:
        beacon_features = [
            row for row in _features_for_scenario(GenerationScenario.FIXED, seed=74)
            if row.label == "beacon"
        ]

        with self.assertRaises(ValueError):
            fit_statistical_baseline(beacon_features)


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


if __name__ == "__main__":
    unittest.main()
