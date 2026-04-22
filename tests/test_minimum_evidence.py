from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.evaluation import (
    MINIMUM_EVIDENCE_EVENT_COUNTS,
    MINIMUM_EVIDENCE_RF_OPERATING_POINTS,
    FeatureCacheConfig,
    build_minimum_evidence_cases,
    export_minimum_evidence_tables,
    run_minimum_evidence_study,
)


class TestMinimumEvidenceStudy(unittest.TestCase):
    def test_event_count_ladder_and_rf_points_are_explicit(self) -> None:
        self.assertEqual(MINIMUM_EVIDENCE_EVENT_COUNTS, (3, 5, 7, 9, 12, 15, 18, 24))
        self.assertEqual(
            MINIMUM_EVIDENCE_RF_OPERATING_POINTS,
            (
                ("rf_full_threshold_0p6", "full", 0.6),
                ("rf_full_threshold_0p3", "full", 0.3),
            ),
        )

    def test_event_count_sweep_keeps_scenario_settings_stable(self) -> None:
        cases = build_minimum_evidence_cases()
        families = {case.scenario_family for case in cases}

        for family in families:
            family_cases = [case for case in cases if case.scenario_family == family]
            first_knobs = _stable_knobs(family_cases[0].config)
            for case in family_cases[1:]:
                self.assertEqual(
                    _stable_knobs(case.config),
                    first_knobs,
                    msg=f"{family} changed a non-event-count knob",
                )
            self.assertEqual(
                [case.event_count for case in family_cases],
                list(MINIMUM_EVIDENCE_EVENT_COUNTS),
            )

    def test_minimum_evidence_runs_and_exports_on_small_inputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/minimum_evidence")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir / "cache",
            mode="test",
            verbose=False,
        )
        cases = build_minimum_evidence_cases(event_counts=(3, 5))[:2]

        result = run_minimum_evidence_study(
            cases=cases,
            seeds=(990,),
            training_seeds=(700,),
            cache_config=cache_config,
        )
        written = export_minimum_evidence_tables(
            output_dir=output_dir,
            result=result,
            cases=cases,
            seeds=(990,),
            training_seeds=(700,),
        )

        self.assertEqual(len(written), 4)
        self.assertGreater(len(result.summary_rows), 0)
        self.assertGreater(len(result.threshold_rows), 0)
        metadata = json.loads(
            (output_dir / "minimum_evidence_metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["feature_schema_version"], "flow_features_v3")
        self.assertIn("fixed_periodic", metadata["scenario_families"])


def _stable_knobs(config: SyntheticTrafficConfig) -> dict[str, object]:
    return {
        "generation_mean_interval": config.mean_interval_seconds,
        "jitter_fraction": config.jitter_fraction,
        "sleep_duration_seconds": config.sleep_duration_seconds,
        "burst_size_min": config.burst_size_min,
        "burst_size_max": config.burst_size_max,
        "beacon_size_jitter_fraction": config.beacon_size_jitter_fraction,
        "time_size_jittered_mean_interval_seconds": config.time_size_jittered_mean_interval_seconds,
        "time_size_jittered_jitter_fraction": config.time_size_jittered_jitter_fraction,
        "time_size_jittered_size_jitter_fraction": config.time_size_jittered_size_jitter_fraction,
        "shortcut_overlap_level": config.shortcut_overlap_level,
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
