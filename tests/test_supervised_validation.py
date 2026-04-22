from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import NormalTrafficProfile, SyntheticTrafficConfig
from beacon_detector.evaluation import (
    EvaluationCase,
    FeatureCacheConfig,
    SupervisedHoldoutExperiment,
    build_supervised_holdout_suite,
    evaluate_supervised_holdout_experiment,
)


class TestSupervisedValidation(unittest.TestCase):
    def test_holdout_suite_contains_expected_pressure_tests(self) -> None:
        suite = build_supervised_holdout_suite()
        names = {experiment.name for experiment in suite}

        self.assertIn("jitter_regime_holdout", names)
        self.assertIn("low_event_count_holdout", names)
        self.assertIn("benign_bursty_profile_holdout", names)
        self.assertIn("time_size_jittered_scenario_holdout", names)

        by_name = {experiment.name: experiment for experiment in suite}
        self.assertIn(
            NormalTrafficProfile.BURSTY_SESSION.value,
            by_name["benign_bursty_profile_holdout"].excluded_training_profiles,
        )
        self.assertIn(
            "time_size_jittered",
            by_name["time_size_jittered_scenario_holdout"].excluded_training_scenarios,
        )

    def test_holdout_experiment_runs_with_separate_training_and_eval_cases(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/supervised_validation")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=200,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=8,
            beacon_event_count=6,
        )
        experiment = SupervisedHoldoutExperiment(
            name="unit_holdout",
            description="Tiny supervised validation holdout.",
            training_cases=(
                EvaluationCase(
                    "unit_train",
                    "Training case.",
                    replace(base, jitter_fraction=0.3),
                ),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "unit_eval",
                    "Evaluation case.",
                    replace(base, jitter_fraction=0.9),
                ),
            ),
        )

        result = evaluate_supervised_holdout_experiment(
            experiment=experiment,
            detector_type="random_forest",
            training_seeds=(201,),
            evaluation_seeds=(301,),
            cache_config=cache_config,
        )

        self.assertEqual(result.experiment.name, "unit_holdout")
        self.assertGreater(result.training_flow_count, 0)
        self.assertGreater(result.training_beacon_flow_count, 0)
        self.assertGreater(result.training_benign_flow_count, 0)
        self.assertGreater(len(result.summary.combined_summary.records), 0)


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
