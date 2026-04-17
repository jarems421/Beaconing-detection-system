from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.detection import AnomalyDetectorConfig
from beacon_detector.evaluation import (
    FeatureCacheConfig,
    build_quick_evaluation_grid,
    build_small_lof_tuning_grid,
    lof_operating_point,
    run_lof_tuning_grid,
    select_best_lof_candidate,
)


class TestLofTuning(unittest.TestCase):
    def test_default_lof_grid_stays_small_and_explicit(self) -> None:
        grid = build_small_lof_tuning_grid()

        self.assertEqual(len(grid), 12)
        self.assertLessEqual(len(grid), 12)
        self.assertTrue(all("local_outlier_factor_v1" in item.name for item in grid))

    def test_lof_operating_point_records_actual_config(self) -> None:
        config = AnomalyDetectorConfig(lof_neighbors=35, contamination=0.05)

        self.assertEqual(
            lof_operating_point(config),
            "lof_neighbors=35;contamination=0.05",
        )

    def test_tuning_grid_runs_and_selects_a_candidate(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/lof_tuning")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        candidates = build_small_lof_tuning_grid(
            neighbor_values=(5,),
            contamination_values=(0.05,),
        )

        results = run_lof_tuning_grid(
            candidates=candidates,
            cases=[build_quick_evaluation_grid()[0]],
            seeds=(71,),
            cache_config=cache_config,
        )
        best = select_best_lof_candidate(results)

        self.assertEqual(len(results), 1)
        self.assertEqual(best.candidate, candidates[0])
        self.assertGreater(len(best.summary.combined_summary.records), 0)


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing_file in output_dir.glob("*"):
        if existing_file.is_file():
            existing_file.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
