from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.evaluation import (
    EvaluationCase,
    FeatureCacheConfig,
    RANDOM_FOREST_THRESHOLD_FEATURE_SETS,
    RANDOM_FOREST_THRESHOLD_VALUES,
    build_random_forest_threshold_feature_sets,
    evaluate_random_forest_threshold_sweep,
)


class TestSupervisedThresholdSweep(unittest.TestCase):
    def test_threshold_sweep_grid_is_small_and_explicit(self) -> None:
        self.assertEqual(RANDOM_FOREST_THRESHOLD_FEATURE_SETS, ("full", "timing_size"))
        self.assertEqual(RANDOM_FOREST_THRESHOLD_VALUES, (0.3, 0.4, 0.5, 0.6, 0.7, 0.8))
        self.assertEqual(
            [feature_set.name for feature_set in build_random_forest_threshold_feature_sets()],
            ["full", "timing_size"],
        )

    def test_random_forest_threshold_sweep_runs_on_existing_pipeline(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/supervised_threshold")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=303,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=8,
            beacon_event_count=6,
        )
        case = EvaluationCase("unit_eval", "Unit evaluation case.", base)
        training_case = EvaluationCase(
            "unit_train",
            "Unit training case.",
            replace(base, seed=703),
        )

        results = evaluate_random_forest_threshold_sweep(
            feature_sets=[build_random_forest_threshold_feature_sets()[0]],
            thresholds=(0.4, 0.6),
            cases=[case],
            training_cases=[training_case],
            seeds=(303,),
            training_seeds=(703,),
            cache_config=cache_config,
        )

        self.assertEqual(len(results), 2)
        self.assertEqual([result.threshold for result in results], [0.4, 0.6])
        self.assertTrue(
            all(len(result.summary.combined_summary.records) > 0 for result in results)
        )


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
