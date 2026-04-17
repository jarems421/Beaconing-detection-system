from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import ShortcutOverlapLevel, SyntheticTrafficConfig
from beacon_detector.evaluation import (
    EvaluationCase,
    FeatureCacheConfig,
    SHORTCUT_STRESS_RF_OPERATING_POINTS,
    build_default_evaluation_grid,
    build_shortcut_stress_suite,
    export_shortcut_stress_tables,
    run_shortcut_stress_comparison,
)


class TestShortcutStressSuite(unittest.TestCase):
    def test_shortcut_stress_suite_is_distinct_from_default_grid(self) -> None:
        default_names = {case.name for case in build_default_evaluation_grid()}
        stress_cases = build_shortcut_stress_suite()

        self.assertGreater(len(stress_cases), 0)
        self.assertTrue(all(case.name not in default_names for case in stress_cases))
        self.assertTrue(
            all(
                case.config.shortcut_overlap_level is not ShortcutOverlapLevel.LOW
                for case in stress_cases
            )
        )

    def test_shortcut_stress_cases_include_low_event_time_size_controls(self) -> None:
        stress_cases = build_shortcut_stress_suite()

        self.assertTrue(
            any(
                case.config.time_size_jittered_event_count is not None
                and case.config.time_size_jittered_event_count <= 6
                for case in stress_cases
            )
        )
        self.assertTrue(
            any(
                case.config.time_size_jittered_jitter_fraction is not None
                and case.config.time_size_jittered_jitter_fraction >= 0.9
                for case in stress_cases
            )
        )

    def test_shortcut_stress_operating_points_are_focused(self) -> None:
        self.assertEqual(
            SHORTCUT_STRESS_RF_OPERATING_POINTS,
            (
                ("rf_full_threshold_0p6", "full", 0.6),
                ("rf_full_threshold_0p3", "full", 0.3),
                ("rf_timing_size_threshold_0p4", "timing_size", 0.4),
            ),
        )

    def test_shortcut_stress_comparison_runs_on_small_case(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/shortcut_stress")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=901,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
            shortcut_overlap_level=ShortcutOverlapLevel.MEDIUM,
            time_size_jittered_event_count=5,
        )
        stress_case = EvaluationCase(
            "unit_shortcut_stress",
            "Small stress case for plumbing tests.",
            base,
        )
        training_case = EvaluationCase(
            "unit_shortcut_training",
            "Small training case for RF plumbing tests.",
            replace(base, seed=701, shortcut_overlap_level=ShortcutOverlapLevel.LOW),
        )

        results = run_shortcut_stress_comparison(
            seeds=(901,),
            training_seeds=(701,),
            stress_cases=[stress_case],
            training_cases=[training_case],
            cache_config=cache_config,
        )

        self.assertEqual(
            [result.detector_name for result in results],
            [
                "rule_baseline_v2_hardened_final",
                "local_outlier_factor_v1",
                "rf_full_threshold_0p6",
                "rf_full_threshold_0p3",
                "rf_timing_size_threshold_0p4",
            ],
        )
        self.assertTrue(
            all(len(result.summary.combined_summary.records) > 0 for result in results)
        )

    def test_shortcut_stress_exports_expected_tables(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/shortcut_stress_export")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=902,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
            shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
            time_size_jittered_event_count=5,
        )
        stress_case = EvaluationCase("unit_export_stress", "Unit export stress.", base)
        training_case = EvaluationCase(
            "unit_export_training",
            "Unit export training.",
            replace(base, seed=702, shortcut_overlap_level=ShortcutOverlapLevel.LOW),
        )
        results = run_shortcut_stress_comparison(
            seeds=(902,),
            training_seeds=(702,),
            stress_cases=[stress_case],
            training_cases=[training_case],
            cache_config=cache_config,
        )

        written_paths = export_shortcut_stress_tables(
            output_dir=output_dir,
            results=results,
            stress_cases=[stress_case],
            seeds=(902,),
            training_seeds=(702,),
            training_cases=[training_case],
        )

        self.assertEqual(len(written_paths), 4)
        self.assertTrue((output_dir / "shortcut_stress_summary.csv").exists())
        self.assertTrue((output_dir / "shortcut_stress_per_case_metrics.csv").exists())
        self.assertTrue((output_dir / "shortcut_stress_profile_rates.csv").exists())
        metadata = json.loads(
            (output_dir / "shortcut_stress_metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["suite_name"], "shortcut_stress_suite")
        self.assertEqual(metadata["evaluation_seed_list"], [902])


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
