from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import ShortcutOverlapLevel, SyntheticTrafficConfig
from beacon_detector.evaluation import (
    FEATURE_IMPROVEMENT_RF_OPERATING_POINTS,
    EvaluationCase,
    FeatureCacheConfig,
    build_shortcut_stress_suite,
    export_feature_improvement_tables,
    run_feature_improvement_evaluation,
)


class TestFeatureImprovementEvaluation(unittest.TestCase):
    def test_feature_improvement_operating_points_are_focused(self) -> None:
        self.assertEqual(
            FEATURE_IMPROVEMENT_RF_OPERATING_POINTS,
            (
                ("rf_full_threshold_0p6", "full", 0.6),
                ("rf_full_threshold_0p3", "full", 0.3),
                ("rf_timing_size_threshold_0p4", "timing_size", 0.4),
            ),
        )

    def test_feature_improvement_evaluation_runs_on_small_inputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_improvement")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=303,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
            shortcut_overlap_level=ShortcutOverlapLevel.MEDIUM,
            time_size_jittered_event_count=5,
        )
        standard_case = EvaluationCase("unit_standard", "Unit standard case.", base)
        stress_case = EvaluationCase(
            "unit_stress",
            "Unit stress case.",
            replace(base, seed=304, shortcut_overlap_level=ShortcutOverlapLevel.HIGH),
        )
        training_case = EvaluationCase(
            "unit_training",
            "Unit training case.",
            replace(base, seed=703, shortcut_overlap_level=ShortcutOverlapLevel.LOW),
        )

        evaluation = run_feature_improvement_evaluation(
            standard_cases=[standard_case],
            shortcut_stress_cases=[stress_case],
            training_cases=[training_case],
            standard_seeds=(303,),
            holdout_evaluation_seeds=(800,),
            shortcut_stress_seeds=(304,),
            training_seeds=(703,),
            cache_config=cache_config,
        )

        self.assertEqual(len(evaluation.standard_results), 3)
        self.assertEqual(len(evaluation.shortcut_stress_results), 3)
        self.assertGreaterEqual(len(evaluation.holdout_results), 3)
        self.assertTrue(
            all(
                len(result.summary.combined_summary.records) > 0
                for result in evaluation.standard_results
            )
        )

    def test_feature_improvement_exports_expected_tables(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_improvement_export")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=305,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
        )
        standard_case = EvaluationCase("unit_standard_export", "Unit standard.", base)
        stress_case = build_shortcut_stress_suite()[0]
        training_case = EvaluationCase(
            "unit_training_export",
            "Unit training.",
            replace(base, seed=705),
        )
        evaluation = run_feature_improvement_evaluation(
            standard_cases=[standard_case],
            shortcut_stress_cases=[stress_case],
            training_cases=[training_case],
            standard_seeds=(305,),
            holdout_evaluation_seeds=(801,),
            shortcut_stress_seeds=(901,),
            training_seeds=(705,),
            cache_config=cache_config,
        )

        written = export_feature_improvement_tables(
            output_dir=output_dir,
            evaluation=evaluation,
            standard_cases=[standard_case],
            shortcut_stress_cases=[stress_case],
            standard_seeds=(305,),
            holdout_evaluation_seeds=(801,),
            shortcut_stress_seeds=(901,),
            training_seeds=(705,),
        )

        self.assertEqual(len(written), 5)
        metadata = json.loads(
            (output_dir / "feature_improvement_metadata.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(metadata["feature_schema_version"], "flow_features_v3")
        self.assertEqual(len(metadata["operating_points"]), 3)


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
