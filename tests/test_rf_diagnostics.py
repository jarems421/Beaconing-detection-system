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
    build_stress_eval_harder_suite,
    build_stress_training_suite,
    diagnostic_group_name,
    export_rf_diagnostic_tables,
    run_rf_time_size_jittered_diagnostic,
    run_stress_trained_rf_experiment,
)


class TestRfDiagnostics(unittest.TestCase):
    def test_diagnostic_group_names_are_explicit(self) -> None:
        self.assertEqual(
            diagnostic_group_name("shortcut_stress", "benign"),
            "missed_shortcut_time_size_jittered",
        )
        self.assertEqual(
            diagnostic_group_name("standard_hardened_grid", "beacon"),
            "detected_standard_time_size_jittered",
        )
        self.assertEqual(
            diagnostic_group_name("supervised_holdout", "benign"),
            "missed_holdout_time_size_jittered",
        )

    def test_stress_train_and_eval_suites_are_distinct(self) -> None:
        training_cases = build_stress_training_suite()
        eval_cases = build_stress_eval_harder_suite()

        training_names = {case.name for case in training_cases}
        eval_names = {case.name for case in eval_cases}

        self.assertTrue(training_names.isdisjoint(eval_names))
        self.assertTrue(
            all(
                case.config.shortcut_overlap_level is ShortcutOverlapLevel.MEDIUM
                for case in training_cases
            )
        )
        self.assertTrue(
            all(
                case.config.shortcut_overlap_level is ShortcutOverlapLevel.HIGH
                for case in eval_cases
            )
        )
        self.assertTrue(
            any(
                (case.config.time_size_jittered_jitter_fraction or 0.0) >= 0.95
                for case in eval_cases
            )
        )

    def test_diagnostic_runs_on_small_inputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/rf_diagnostics")
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
            time_size_jittered_event_count=5,
        )
        standard_case = EvaluationCase("unit_standard", "Unit standard.", base)
        stress_case = EvaluationCase(
            "unit_stress",
            "Unit stress.",
            replace(
                base,
                seed=902,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
            ),
        )
        training_case = EvaluationCase(
            "unit_training",
            "Unit training.",
            replace(base, seed=701),
        )

        result = run_rf_time_size_jittered_diagnostic(
            standard_cases=[standard_case],
            shortcut_stress_cases=[stress_case],
            training_cases=[training_case],
            standard_seeds=(301,),
            shortcut_stress_seeds=(901,),
            holdout_evaluation_seeds=(801,),
            training_seeds=(701,),
            cache_config=cache_config,
        )

        self.assertGreater(len(result.flow_records), 0)
        self.assertGreater(len(result.group_summaries), 0)
        self.assertTrue(
            all("time_size_jittered" in record.group_name for record in result.flow_records)
        )

    def test_stress_training_experiment_and_exports_run_on_small_inputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/rf_diagnostic_export")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=903,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
            time_size_jittered_event_count=5,
        )
        baseline_training = [
            EvaluationCase("unit_baseline_training", "Baseline training.", base)
        ]
        stress_training = [
            EvaluationCase(
                "unit_stress_training",
                "Stress training.",
                replace(base, seed=704, shortcut_overlap_level=ShortcutOverlapLevel.MEDIUM),
            )
        ]
        stress_eval = [
            EvaluationCase(
                "unit_stress_eval",
                "Stress evaluation.",
                replace(
                    base,
                    seed=904,
                    shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                    time_size_jittered_jitter_fraction=0.95,
                    time_size_jittered_size_jitter_fraction=0.95,
                ),
            )
        ]
        diagnostic = run_rf_time_size_jittered_diagnostic(
            standard_cases=baseline_training,
            shortcut_stress_cases=stress_eval,
            training_cases=baseline_training,
            standard_seeds=(303,),
            shortcut_stress_seeds=(904,),
            holdout_evaluation_seeds=(802,),
            training_seeds=(703,),
            cache_config=cache_config,
        )
        stress_results = run_stress_trained_rf_experiment(
            baseline_training_cases=baseline_training,
            stress_training_cases=stress_training,
            stress_eval_cases=stress_eval,
            evaluation_seeds=(904,),
            training_seeds=(703,),
            cache_config=cache_config,
        )

        written = export_rf_diagnostic_tables(
            output_dir=output_dir,
            diagnostic=diagnostic,
            stress_results=stress_results,
            stress_training_cases=stress_training,
            stress_eval_cases=stress_eval,
            training_seeds=(703,),
            evaluation_seeds=(904,),
        )

        self.assertEqual(len(written), 6)
        self.assertTrue((output_dir / "rf_time_size_jittered_diagnostic_summary.csv").exists())
        self.assertTrue((output_dir / "rf_stress_training_comparison.csv").exists())
        metadata = json.loads(
            (output_dir / "diagnostic_metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["feature_schema_version"], "flow_features_v3")
        self.assertEqual(metadata["stress_training_case_names"], ["unit_stress_training"])
        self.assertEqual(metadata["stress_eval_case_names"], ["unit_stress_eval"])


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
