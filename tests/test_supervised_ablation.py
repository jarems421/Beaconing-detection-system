from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.evaluation import (
    BURST_FEATURES,
    SIZE_FEATURES,
    TIMING_FEATURES,
    EvaluationCase,
    FeatureCacheConfig,
    SupervisedHoldoutExperiment,
    build_supervised_ablation_feature_sets,
    evaluate_supervised_ablation_grid,
    evaluate_supervised_holdout_ablation_grid,
    feature_set_by_name,
)


class TestSupervisedAblation(unittest.TestCase):
    def test_required_feature_sets_are_explicit(self) -> None:
        feature_sets = build_supervised_ablation_feature_sets()

        self.assertEqual(
            [feature_set.name for feature_set in feature_sets],
            [
                "full",
                "without_event_count",
                "without_size_cv",
                "without_event_count_and_size_cv",
                "timing_only",
                "timing_burst",
                "timing_size",
                "timing_burst_size",
            ],
        )

    def test_shortcut_ablation_feature_lists_are_correct(self) -> None:
        full = feature_set_by_name("full")
        without_event_count = feature_set_by_name("without_event_count")
        without_size_cv = feature_set_by_name("without_size_cv")
        without_both = feature_set_by_name("without_event_count_and_size_cv")

        self.assertIn("event_count", full.feature_names)
        self.assertIn("size_cv", full.feature_names)
        self.assertIn("interarrival_within_10pct_median_fraction", full.feature_names)
        self.assertIn("dominant_interval_bin_fraction", full.feature_names)
        self.assertIn("adjacent_gap_similarity_fraction", full.feature_names)
        self.assertIn("dominant_size_bin_fraction", full.feature_names)
        self.assertNotIn("event_count", without_event_count.feature_names)
        self.assertIn("size_cv", without_event_count.feature_names)
        self.assertIn("event_count", without_size_cv.feature_names)
        self.assertNotIn("size_cv", without_size_cv.feature_names)
        self.assertNotIn("event_count", without_both.feature_names)
        self.assertNotIn("size_cv", without_both.feature_names)

    def test_grouped_feature_sets_are_correct(self) -> None:
        timing_only = feature_set_by_name("timing_only")
        timing_burst = feature_set_by_name("timing_burst")
        timing_size = feature_set_by_name("timing_size")
        timing_burst_size = feature_set_by_name("timing_burst_size")

        self.assertEqual(timing_only.feature_names, TIMING_FEATURES)
        self.assertTrue(set(TIMING_FEATURES).issubset(timing_burst.feature_names))
        self.assertTrue(set(BURST_FEATURES).issubset(timing_burst.feature_names))
        self.assertTrue(set(TIMING_FEATURES).issubset(timing_size.feature_names))
        self.assertTrue(set(SIZE_FEATURES).issubset(timing_size.feature_names))
        self.assertTrue(set(BURST_FEATURES).issubset(timing_burst_size.feature_names))
        self.assertTrue(set(SIZE_FEATURES).issubset(timing_burst_size.feature_names))
        self.assertNotIn("event_count", timing_burst_size.feature_names)

    def test_standard_ablation_grid_runs_on_existing_pipeline(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/supervised_ablation/standard")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=301,
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
            replace(base, seed=701),
        )

        results = evaluate_supervised_ablation_grid(
            detector_types=("random_forest",),
            feature_sets=[feature_set_by_name("without_event_count")],
            cases=[case],
            training_cases=[training_case],
            seeds=(301,),
            training_seeds=(701,),
            cache_config=cache_config,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].feature_set.name, "without_event_count")
        self.assertGreater(len(results[0].summary.combined_summary.records), 0)

    def test_holdout_ablation_grid_runs_on_existing_pipeline(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/supervised_ablation/holdout")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=302,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=8,
            beacon_event_count=6,
        )
        experiment = SupervisedHoldoutExperiment(
            name="unit_holdout",
            description="Small holdout ablation.",
            training_cases=(
                EvaluationCase("unit_train", "Training case.", base),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "unit_eval",
                    "Evaluation case.",
                    replace(base, jitter_fraction=0.9),
                ),
            ),
        )

        results = evaluate_supervised_holdout_ablation_grid(
            detector_types=("logistic_regression",),
            feature_sets=[feature_set_by_name("timing_only")],
            experiments=[experiment],
            training_seeds=(702,),
            evaluation_seeds=(802,),
            cache_config=cache_config,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].feature_set.name, "timing_only")
        self.assertGreater(
            len(results[0].holdout_result.summary.combined_summary.records),
            0,
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
