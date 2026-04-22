from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.data import (
    NormalTrafficProfile,
    ShortcutOverlapLevel,
    SyntheticTrafficConfig,
)
from beacon_detector.detection import (
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    LOCAL_OUTLIER_FACTOR_NAME,
    AnomalyDetectorConfig,
    SupervisedDetectorConfig,
)

from .cache import FeatureCacheConfig
from .runner import (
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    MultiSeedEvaluationSummary,
    build_default_evaluation_grid,
    evaluate_anomaly_detector_multi_seed,
    evaluate_rule_detector_multi_seed,
    evaluate_supervised_detector_multi_seed,
)
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name

SHORTCUT_STRESS_SEEDS = (900, 901, 902)
SHORTCUT_STRESS_RF_OPERATING_POINTS = (
    ("rf_full_threshold_0p6", "full", 0.6),
    ("rf_full_threshold_0p3", "full", 0.3),
    ("rf_timing_size_threshold_0p4", "timing_size", 0.4),
)


@dataclass(frozen=True, slots=True)
class ShortcutStressDetectorResult:
    detector_name: str
    operating_point: str
    summary: MultiSeedEvaluationSummary
    feature_set: SupervisedFeatureSet | None = None


def build_shortcut_stress_suite(
    start_time: datetime | None = None,
) -> list[EvaluationCase]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=900,
        normal_event_count=180,
        normal_flow_count=28,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=9,
        beacon_event_count=8,
        mean_interval_seconds=60.0,
        duration_seconds=5400,
        beacon_size_bytes=150,
    )

    overlap_profiles = (
        NormalTrafficProfile.KEEPALIVE,
        NormalTrafficProfile.TELEMETRY,
        NormalTrafficProfile.API_POLLING,
        NormalTrafficProfile.BURSTY_SESSION,
        NormalTrafficProfile.SOFTWARE_UPDATE,
    )

    return [
        EvaluationCase(
            name="overlap_medium_low_event",
            description=(
                "Medium shortcut overlap with benign and beacon flows sharing "
                "similar event-count ranges."
            ),
            config=replace(
                base,
                seed=910,
                shortcut_overlap_level=ShortcutOverlapLevel.MEDIUM,
                beacon_event_count=6,
                normal_event_count=160,
                normal_flow_count=26,
                normal_events_per_flow_min=4,
                normal_events_per_flow_max=8,
                time_size_jittered_event_count=6,
                time_size_jittered_jitter_fraction=0.65,
                time_size_jittered_size_jitter_fraction=0.65,
                normal_profiles=overlap_profiles,
            ),
        ),
        EvaluationCase(
            name="overlap_high_low_event",
            description=(
                "High shortcut overlap with low-event beacon flows and "
                "multi-event benign flows."
            ),
            config=replace(
                base,
                seed=911,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                beacon_event_count=5,
                normal_event_count=170,
                normal_flow_count=30,
                normal_events_per_flow_min=4,
                normal_events_per_flow_max=7,
                time_size_jittered_event_count=5,
                time_size_jittered_jitter_fraction=0.90,
                time_size_jittered_size_jitter_fraction=0.85,
                normal_profiles=overlap_profiles,
            ),
        ),
        EvaluationCase(
            name="overlap_high_size_duration",
            description=(
                "High overlap in size variation and duration-like timing while "
                "keeping benign profiles explicitly labelled."
            ),
            config=replace(
                base,
                seed=912,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                beacon_event_count=8,
                normal_event_count=190,
                normal_flow_count=30,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=9,
                mean_interval_seconds=75.0,
                beacon_size_bytes=180,
                beacon_size_jitter_fraction=0.55,
                time_size_jittered_event_count=7,
                time_size_jittered_mean_interval_seconds=75.0,
                time_size_jittered_jitter_fraction=0.80,
                time_size_jittered_size_jitter_fraction=0.80,
                normal_profiles=overlap_profiles,
            ),
        ),
        EvaluationCase(
            name="hard_time_size_jittered_overlap",
            description=(
                "Harder time+size jittered beacons with low events, high jitter, "
                "and size variation overlapping benign telemetry/update traffic."
            ),
            config=replace(
                base,
                seed=913,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                beacon_event_count=8,
                normal_event_count=190,
                normal_flow_count=30,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=9,
                mean_interval_seconds=70.0,
                beacon_size_bytes=170,
                beacon_size_jitter_fraction=0.70,
                time_size_jittered_event_count=5,
                time_size_jittered_mean_interval_seconds=70.0,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
                normal_profiles=overlap_profiles,
            ),
        ),
        EvaluationCase(
            name="benign_shortcut_profile_mix",
            description=(
                "High-overlap benign keepalive, telemetry, API polling, bursty "
                "session, and software-update traffic in one class-imbalanced mix."
            ),
            config=replace(
                base,
                seed=914,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                normal_event_count=280,
                normal_flow_count=42,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=8,
                beacon_event_count=6,
                time_size_jittered_event_count=5,
                time_size_jittered_jitter_fraction=0.90,
                time_size_jittered_size_jitter_fraction=0.90,
                normal_profiles=overlap_profiles,
            ),
        ),
    ]


def run_shortcut_stress_comparison(
    *,
    seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    stress_cases: list[EvaluationCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
) -> list[ShortcutStressDetectorResult]:
    stress_cases = stress_cases or build_shortcut_stress_suite()
    training_cases = training_cases or build_default_evaluation_grid()

    results = [
        ShortcutStressDetectorResult(
            detector_name=FROZEN_RULE_BASELINE_NAME,
            operating_point=(
                f"threshold={FROZEN_RULE_BASELINE_THRESHOLDS.prediction_threshold:g}"
            ),
            summary=evaluate_rule_detector_multi_seed(
                seeds=seeds,
                thresholds=FROZEN_RULE_BASELINE_THRESHOLDS,
                cases=stress_cases,
                cache_config=cache_config,
            ),
        ),
        ShortcutStressDetectorResult(
            detector_name=LOCAL_OUTLIER_FACTOR_NAME,
            operating_point="default_lof",
            summary=evaluate_anomaly_detector_multi_seed(
                "local_outlier_factor",
                seeds=seeds,
                config=AnomalyDetectorConfig(),
                cases=stress_cases,
                cache_config=cache_config,
            ),
        ),
    ]

    for result_name, feature_set_name, threshold in SHORTCUT_STRESS_RF_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        results.append(
            ShortcutStressDetectorResult(
                detector_name=result_name,
                operating_point=f"threshold={threshold:g};features={feature_set.name}",
                feature_set=feature_set,
                summary=evaluate_supervised_detector_multi_seed(
                    "random_forest",
                    seeds=seeds,
                    config=config,
                    cases=stress_cases,
                    training_seeds=training_seeds,
                    training_cases=training_cases,
                    cache_config=cache_config,
                ),
            )
        )

    return results


def export_shortcut_stress_tables(
    *,
    output_dir: str | Path,
    results: list[ShortcutStressDetectorResult],
    stress_cases: list[EvaluationCase],
    seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    training_cases: list[EvaluationCase] | None = None,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    training_cases = training_cases or build_default_evaluation_grid()
    return [
        _write_summary(output_path, results),
        _write_per_case_metrics(output_path, results),
        _write_profile_rates(output_path, results),
        _write_metadata(
            output_path,
            results=results,
            stress_cases=stress_cases,
            training_cases=training_cases,
            seeds=seeds,
            training_seeds=training_seeds,
        ),
    ]


def _write_summary(
    output_dir: Path,
    results: list[ShortcutStressDetectorResult],
) -> Path:
    path = output_dir / "shortcut_stress_summary.csv"
    rows = [
        {
            "detector_name": result.detector_name,
            "operating_point": result.operating_point,
            "feature_set": result.feature_set.name if result.feature_set else "",
            **_metrics_row(result.summary),
        }
        for result in results
    ]
    _write_csv(path, rows)
    return path


def _write_per_case_metrics(
    output_dir: Path,
    results: list[ShortcutStressDetectorResult],
) -> Path:
    path = output_dir / "shortcut_stress_per_case_metrics.csv"
    rows: list[dict[str, Any]] = []
    for result in results:
        for case_metric in result.summary.combined_summary.per_case_metrics:
            rows.append(
                {
                    "detector_name": result.detector_name,
                    "operating_point": result.operating_point,
                    "feature_set": result.feature_set.name if result.feature_set else "",
                    "case_name": case_metric.case_name,
                    **_case_metrics_row(case_metric),
                }
            )
    _write_csv(path, rows)
    return path


def _write_profile_rates(
    output_dir: Path,
    results: list[ShortcutStressDetectorResult],
) -> Path:
    path = output_dir / "shortcut_stress_profile_rates.csv"
    rows: list[dict[str, Any]] = []
    for result in results:
        for rate in result.summary.combined_summary.per_scenario_rates:
            rows.append(
                {
                    "detector_name": result.detector_name,
                    "operating_point": result.operating_point,
                    "feature_set": result.feature_set.name if result.feature_set else "",
                    "scenario_or_profile_name": rate.scenario_name,
                    "category": (
                        "benign_profile"
                        if rate.true_beacon_flows == 0
                        else "beacon"
                    ),
                    "rate_type": (
                        "false_flag_rate"
                        if rate.true_beacon_flows == 0
                        else "detection_rate"
                    ),
                    "total_flows": rate.total_flows,
                    "true_beacon_flows": rate.true_beacon_flows,
                    "predicted_beacon_flows": rate.predicted_beacon_flows,
                    "rate": rate.detection_rate,
                }
            )
    _write_csv(path, rows)
    return path


def _write_metadata(
    output_dir: Path,
    *,
    results: list[ShortcutStressDetectorResult],
    stress_cases: list[EvaluationCase],
    training_cases: list[EvaluationCase],
    seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "shortcut_stress_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "suite_name": "shortcut_stress_suite",
        "purpose": (
            "Stress current RF operating points under explicit event-count, "
            "size-variation, duration, and time_size_jittered overlap."
        ),
        "evaluation_seed_list": list(seeds),
        "supervised_training_seed_list": list(training_seeds),
        "stress_case_names": [case.name for case in stress_cases],
        "training_case_names": [case.name for case in training_cases],
        "detectors": [
            {
                "detector_name": result.detector_name,
                "operating_point": result.operating_point,
                "feature_set": (
                    asdict(result.feature_set) if result.feature_set else None
                ),
            }
            for result in results
        ],
        "difficulty_controls": [
            {
                "case_name": case.name,
                "shortcut_overlap_level": ShortcutOverlapLevel(
                    case.config.shortcut_overlap_level
                ).value,
                "beacon_event_count": case.config.beacon_event_count,
                "normal_events_per_flow_min": case.config.normal_events_per_flow_min,
                "normal_events_per_flow_max": case.config.normal_events_per_flow_max,
                "time_size_jittered_event_count": (
                    case.config.time_size_jittered_event_count
                ),
                "time_size_jittered_jitter_fraction": (
                    case.config.time_size_jittered_jitter_fraction
                ),
                "time_size_jittered_size_jitter_fraction": (
                    case.config.time_size_jittered_size_jitter_fraction
                ),
            }
            for case in stress_cases
        ],
        "outputs": [
            "shortcut_stress_summary.csv",
            "shortcut_stress_per_case_metrics.csv",
            "shortcut_stress_profile_rates.csv",
            "shortcut_stress_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _metrics_row(summary: MultiSeedEvaluationSummary) -> dict[str, float | int]:
    metrics = summary.combined_summary.overall_metrics
    matrix = metrics.confusion_matrix
    spread = summary.metric_spread
    return {
        "mean_precision": spread.mean_precision,
        "std_precision": spread.std_precision,
        "mean_recall": spread.mean_recall,
        "std_recall": spread.std_recall,
        "mean_f1": spread.mean_f1_score,
        "std_f1": spread.std_f1_score,
        "mean_false_positive_rate": spread.mean_false_positive_rate,
        "std_false_positive_rate": spread.std_false_positive_rate,
        "combined_precision": metrics.precision,
        "combined_recall": metrics.recall,
        "combined_f1": metrics.f1_score,
        "combined_false_positive_rate": metrics.false_positive_rate,
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
    }


def _case_metrics_row(case_metric) -> dict[str, float | int]:
    metrics = case_metric.metrics
    matrix = metrics.confusion_matrix
    return {
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1_score,
        "false_positive_rate": metrics.false_positive_rate,
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "total_flows": case_metric.total_flows,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
