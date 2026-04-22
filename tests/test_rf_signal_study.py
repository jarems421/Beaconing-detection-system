from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.evaluation import (
    DURATION_MEAN_INTERVAL_VALUES,
    EVENT_COUNT_VALUES,
    RF_SIGNAL_STUDY_OPERATING_POINTS,
    SIZE_JITTER_VALUES,
    TIMING_JITTER_VALUES,
    EvaluationCase,
    FeatureCacheConfig,
    build_signal_study_base_config,
    build_time_size_signal_study_cases,
    export_rf_time_size_signal_study_tables,
    run_rf_time_size_signal_study,
)


class TestRfSignalStudy(unittest.TestCase):
    def test_signal_study_factor_values_are_explicit(self) -> None:
        self.assertEqual(EVENT_COUNT_VALUES, (5, 7, 9, 12, 15))
        self.assertEqual(TIMING_JITTER_VALUES, (0.30, 0.50, 0.70, 0.95))
        self.assertEqual(SIZE_JITTER_VALUES, (0.20, 0.40, 0.70, 0.95))
        self.assertEqual(DURATION_MEAN_INTERVAL_VALUES, (35.0, 55.0, 80.0, 120.0))
        self.assertEqual(
            RF_SIGNAL_STUDY_OPERATING_POINTS,
            (
                ("rf_full_threshold_0p6", "full", 0.6),
                ("rf_full_threshold_0p3", "full", 0.3),
            ),
        )

    def test_one_factor_sweeps_keep_other_knobs_fixed(self) -> None:
        base = build_signal_study_base_config()
        base_knobs = _knobs(base)
        cases = build_time_size_signal_study_cases()

        target_by_factor = {
            "event_count": "event_count",
            "timing_jitter": "timing_jitter",
            "size_jitter": "size_jitter",
            "duration_mean_interval": "mean_interval",
            "benign_overlap": "overlap_level",
            "timing_size_interaction": None,
        }

        for study_case in cases:
            knobs = _knobs(study_case.case.config)
            target = target_by_factor[study_case.factor_name]
            for knob_name, base_value in base_knobs.items():
                if target is None and knob_name in {"timing_jitter", "size_jitter"}:
                    continue
                if knob_name == target:
                    continue
                self.assertEqual(
                    knobs[knob_name],
                    base_value,
                    msg=f"{study_case.factor_name} changed {knob_name}",
                )

    def test_signal_study_runs_and_exports_on_small_inputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/rf_signal_study")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        base = SyntheticTrafficConfig(
            seed=991,
            normal_event_count=36,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=7,
            beacon_event_count=5,
            time_size_jittered_event_count=5,
            time_size_jittered_jitter_fraction=0.95,
            time_size_jittered_size_jitter_fraction=0.95,
        )
        study_cases = build_time_size_signal_study_cases()[:2]
        training_case = EvaluationCase(
            "unit_signal_training",
            "Unit signal training.",
            replace(base, seed=701),
        )

        result = run_rf_time_size_signal_study(
            study_cases=study_cases,
            training_cases=[training_case],
            seeds=(991,),
            training_seeds=(701,),
            cache_config=cache_config,
        )
        written = export_rf_time_size_signal_study_tables(
            output_dir=output_dir,
            result=result,
            study_cases=study_cases,
            seeds=(991,),
            training_seeds=(701,),
        )

        self.assertEqual(len(written), 3)
        self.assertGreater(len(result.summary_rows), 0)
        metadata = json.loads(
            (output_dir / "rf_time_size_signal_study_metadata.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(metadata["feature_schema_version"], "flow_features_v3")
        self.assertIn("event_count", metadata["factor_values"])


def _knobs(config: SyntheticTrafficConfig) -> dict[str, object]:
    return {
        "event_count": config.time_size_jittered_event_count,
        "mean_interval": config.time_size_jittered_mean_interval_seconds,
        "timing_jitter": config.time_size_jittered_jitter_fraction,
        "size_jitter": config.time_size_jittered_size_jitter_fraction,
        "overlap_level": config.shortcut_overlap_level,
    }


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
