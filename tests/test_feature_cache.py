from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.evaluation import (
    EvaluationCase,
    FeatureCacheConfig,
    evaluate_rule_detector,
    get_or_build_feature_rows,
)
from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey


class TestFeatureCache(unittest.TestCase):
    def test_cache_miss_then_hit_reuses_feature_rows(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_cache/miss_hit")
        config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        build_count = {"value": 0}

        def build_rows() -> list[FlowFeatures]:
            build_count["value"] += 1
            return [_feature_row()]

        source_config = SyntheticTrafficConfig(seed=91)
        first = get_or_build_feature_rows(
            cache_config=config,
            cache_kind="evaluation_case",
            cache_name="unit_case",
            seed=91,
            source_config=source_config,
            build_rows=build_rows,
        )
        second = get_or_build_feature_rows(
            cache_config=config,
            cache_kind="evaluation_case",
            cache_name="unit_case",
            seed=91,
            source_config=source_config,
            build_rows=build_rows,
        )

        self.assertEqual(first.status, "miss")
        self.assertEqual(second.status, "hit")
        self.assertEqual(build_count["value"], 1)
        self.assertEqual(second.rows[0].flow_key, _feature_row().flow_key)

    def test_cache_version_mismatch_is_treated_as_stale(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_cache/stale")
        source_config = SyntheticTrafficConfig(seed=92)
        first_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            cache_version="version_a",
            verbose=False,
        )
        second_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            cache_version="version_b",
            verbose=False,
        )
        build_count = {"value": 0}

        def build_rows() -> list[FlowFeatures]:
            build_count["value"] += 1
            return [_feature_row(event_count=build_count["value"])]

        get_or_build_feature_rows(
            cache_config=first_config,
            cache_kind="benign_reference",
            cache_name="unit_reference",
            seed=92,
            source_config=source_config,
            build_rows=build_rows,
        )
        second = get_or_build_feature_rows(
            cache_config=second_config,
            cache_kind="benign_reference",
            cache_name="unit_reference",
            seed=92,
            source_config=source_config,
            build_rows=build_rows,
        )

        self.assertEqual(second.status, "stale")
        self.assertEqual(build_count["value"], 2)
        self.assertEqual(second.rows[0].event_count, 2)

    def test_feature_schema_change_does_not_reuse_old_cache_file(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_cache/schema")
        source_config = SyntheticTrafficConfig(seed=94)
        first_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            feature_schema_version="schema_a",
            verbose=False,
        )
        second_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            feature_schema_version="schema_b",
            verbose=False,
        )
        build_count = {"value": 0}

        def build_rows() -> list[FlowFeatures]:
            build_count["value"] += 1
            return [_feature_row(event_count=build_count["value"])]

        first = get_or_build_feature_rows(
            cache_config=first_config,
            cache_kind="evaluation_case",
            cache_name="unit_schema_case",
            seed=94,
            source_config=source_config,
            build_rows=build_rows,
        )
        second = get_or_build_feature_rows(
            cache_config=second_config,
            cache_kind="evaluation_case",
            cache_name="unit_schema_case",
            seed=94,
            source_config=source_config,
            build_rows=build_rows,
        )

        self.assertEqual(first.status, "miss")
        self.assertEqual(second.status, "miss")
        self.assertEqual(build_count["value"], 2)
        self.assertEqual(len(list(output_dir.glob("*.json"))), 2)

    def test_evaluation_can_reuse_cached_case_features(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/feature_cache/evaluation")
        cache_config = FeatureCacheConfig(
            cache_dir=output_dir,
            mode="test",
            verbose=False,
        )
        case = EvaluationCase(
            "cache_case",
            "Small cache reuse case.",
            SyntheticTrafficConfig(
                start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                seed=93,
                normal_event_count=30,
                normal_flow_count=6,
                beacon_event_count=6,
            ),
        )

        first = evaluate_rule_detector([case], cache_config=cache_config)
        second = evaluate_rule_detector([case], cache_config=cache_config)

        self.assertEqual(first.overall_metrics, second.overall_metrics)
        self.assertTrue(any(output_dir.glob("evaluation_case_test_cache_case_*.json")))


def _feature_row(event_count: int = 3) -> FlowFeatures:
    return FlowFeatures(
        flow_key=FlowKey(
            src_ip="10.0.0.1",
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="tcp",
        ),
        label="benign",
        scenario_name="normal_test",
        event_count=event_count,
        total_bytes=300,
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
