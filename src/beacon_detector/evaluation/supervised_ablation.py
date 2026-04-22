from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection import (
    DEFAULT_SUPERVISED_FEATURES,
    SupervisedDetectorConfig,
    SupervisedDetectorType,
)

from .cache import FeatureCacheConfig
from .runner import (
    FROZEN_BASELINE_SEEDS,
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    MultiSeedEvaluationSummary,
    build_default_evaluation_grid,
    evaluate_supervised_detector_multi_seed,
)
from .supervised_validation import (
    SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    SupervisedHoldoutExperiment,
    SupervisedHoldoutResult,
    build_supervised_holdout_suite,
    evaluate_supervised_holdout_experiment,
)

TIMING_FEATURES = (
    "flow_duration_seconds",
    "inter_arrival_cv",
    "trimmed_interarrival_cv",
    "interarrival_iqr_seconds",
    "interarrival_mad_seconds",
    "near_median_interarrival_fraction",
    "interarrival_within_10pct_median_fraction",
    "interarrival_within_20pct_median_fraction",
    "interarrival_within_30pct_median_fraction",
    "dominant_interval_fraction",
    "dominant_interval_bin_fraction",
    "interval_bin_count",
    "adjacent_gap_similarity_fraction",
    "longest_similar_gap_run",
    "gap_range_median_ratio",
    "interarrival_median_absolute_percentage_deviation",
    "periodicity_score",
)
BURST_FEATURES = (
    "burst_count",
    "avg_burst_size",
    "burst_size_cv",
    "sleep_duration_cv",
    "within_burst_gap_consistency",
    "burst_to_idle_ratio",
)
SIZE_FEATURES = (
    "size_cv",
    "dominant_size_bin_fraction",
    "size_bin_count",
    "normalized_size_range",
    "near_median_size_fraction",
)


@dataclass(frozen=True, slots=True)
class SupervisedFeatureSet:
    name: str
    description: str
    feature_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SupervisedAblationResult:
    feature_set: SupervisedFeatureSet
    detector_type: SupervisedDetectorType
    summary: MultiSeedEvaluationSummary


@dataclass(frozen=True, slots=True)
class SupervisedHoldoutAblationResult:
    feature_set: SupervisedFeatureSet
    holdout_result: SupervisedHoldoutResult


def build_supervised_ablation_feature_sets() -> list[SupervisedFeatureSet]:
    full_features = tuple(DEFAULT_SUPERVISED_FEATURES)
    timing_burst_size = _unique_features(
        TIMING_FEATURES + BURST_FEATURES + SIZE_FEATURES
    )
    return [
        SupervisedFeatureSet(
            name="full",
            description="Current full supervised behavioural feature set.",
            feature_names=full_features,
        ),
        SupervisedFeatureSet(
            name="without_event_count",
            description="Full set excluding event_count.",
            feature_names=_without(full_features, {"event_count"}),
        ),
        SupervisedFeatureSet(
            name="without_size_cv",
            description="Full set excluding size_cv.",
            feature_names=_without(full_features, {"size_cv"}),
        ),
        SupervisedFeatureSet(
            name="without_event_count_and_size_cv",
            description="Full set excluding both event_count and size_cv.",
            feature_names=_without(full_features, {"event_count", "size_cv"}),
        ),
        SupervisedFeatureSet(
            name="timing_only",
            description="Timing and periodicity features only.",
            feature_names=TIMING_FEATURES,
        ),
        SupervisedFeatureSet(
            name="timing_burst",
            description="Timing plus burst-shape features.",
            feature_names=_unique_features(TIMING_FEATURES + BURST_FEATURES),
        ),
        SupervisedFeatureSet(
            name="timing_size",
            description="Timing plus size-variation features.",
            feature_names=_unique_features(TIMING_FEATURES + SIZE_FEATURES),
        ),
        SupervisedFeatureSet(
            name="timing_burst_size",
            description="Timing, burst, and size features without event_count.",
            feature_names=timing_burst_size,
        ),
    ]


def feature_set_by_name(name: str) -> SupervisedFeatureSet:
    for feature_set in build_supervised_ablation_feature_sets():
        if feature_set.name == name:
            return feature_set
    raise ValueError(f"Unknown supervised ablation feature set: {name}")


def evaluate_supervised_ablation_grid(
    *,
    detector_types: tuple[SupervisedDetectorType, ...] = (
        "random_forest",
        "logistic_regression",
    ),
    feature_sets: list[SupervisedFeatureSet] | None = None,
    base_config: SupervisedDetectorConfig | None = None,
    cases: list[EvaluationCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[SupervisedAblationResult]:
    feature_sets = feature_sets or build_supervised_ablation_feature_sets()
    base_config = base_config or SupervisedDetectorConfig()
    cases = cases or build_default_evaluation_grid()
    training_cases = training_cases or cases

    results: list[SupervisedAblationResult] = []
    for feature_set in feature_sets:
        config = replace(base_config, feature_names=feature_set.feature_names)
        for detector_type in detector_types:
            results.append(
                SupervisedAblationResult(
                    feature_set=feature_set,
                    detector_type=detector_type,
                    summary=evaluate_supervised_detector_multi_seed(
                        detector_type,
                        seeds=seeds,
                        config=config,
                        cases=cases,
                        training_seeds=training_seeds,
                        training_cases=training_cases,
                        cache_config=cache_config,
                    ),
                )
            )
    return results


def evaluate_supervised_holdout_ablation_grid(
    *,
    detector_types: tuple[SupervisedDetectorType, ...] = (
        "random_forest",
        "logistic_regression",
    ),
    feature_sets: list[SupervisedFeatureSet] | None = None,
    experiments: list[SupervisedHoldoutExperiment] | None = None,
    base_config: SupervisedDetectorConfig | None = None,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[SupervisedHoldoutAblationResult]:
    feature_sets = feature_sets or build_supervised_ablation_feature_sets()
    experiments = experiments or build_supervised_holdout_suite()
    base_config = base_config or SupervisedDetectorConfig()

    results: list[SupervisedHoldoutAblationResult] = []
    for feature_set in feature_sets:
        config = replace(base_config, feature_names=feature_set.feature_names)
        for detector_type in detector_types:
            for experiment in experiments:
                results.append(
                    SupervisedHoldoutAblationResult(
                        feature_set=feature_set,
                        holdout_result=evaluate_supervised_holdout_experiment(
                            experiment=experiment,
                            detector_type=detector_type,
                            config=config,
                            training_seeds=training_seeds,
                            evaluation_seeds=evaluation_seeds,
                            cache_config=cache_config,
                        ),
                    )
                )
    return results


def export_supervised_ablation_tables(
    *,
    output_dir: str | Path,
    standard_results: list[SupervisedAblationResult],
    holdout_results: list[SupervisedHoldoutAblationResult],
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    holdout_evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    written_paths = [
        _write_standard_summary(output_path, standard_results),
        _write_holdout_summary(output_path, holdout_results),
        _write_per_case_metrics(output_path, standard_results, holdout_results),
        _write_per_scenario_rates(output_path, standard_results, holdout_results),
        _write_metadata(
            output_path,
            standard_results=standard_results,
            holdout_results=holdout_results,
            training_seeds=training_seeds,
            evaluation_seeds=evaluation_seeds,
            holdout_evaluation_seeds=holdout_evaluation_seeds,
        ),
    ]
    return written_paths


def _write_standard_summary(
    output_dir: Path,
    results: list[SupervisedAblationResult],
) -> Path:
    path = output_dir / "supervised_ablation_summary.csv"
    rows = []
    for result in results:
        rows.append(
            {
                "evaluation_scope": "standard_hardened_grid",
                "feature_set": result.feature_set.name,
                "detector_type": result.detector_type,
                **_metrics_row(result.summary),
            }
        )
    _write_csv(path, rows)
    return path


def _write_holdout_summary(
    output_dir: Path,
    results: list[SupervisedHoldoutAblationResult],
) -> Path:
    path = output_dir / "supervised_ablation_holdout_summary.csv"
    rows = []
    for result in results:
        holdout = result.holdout_result
        rows.append(
            {
                "evaluation_scope": "supervised_holdout",
                "holdout_experiment": holdout.experiment.name,
                "feature_set": result.feature_set.name,
                "detector_type": holdout.detector_type,
                "training_flow_count": holdout.training_flow_count,
                "training_beacon_flow_count": holdout.training_beacon_flow_count,
                "training_benign_flow_count": holdout.training_benign_flow_count,
                **_metrics_row(holdout.summary),
            }
        )
    _write_csv(path, rows)
    return path


def _write_per_case_metrics(
    output_dir: Path,
    standard_results: list[SupervisedAblationResult],
    holdout_results: list[SupervisedHoldoutAblationResult],
) -> Path:
    path = output_dir / "supervised_ablation_per_case_metrics.csv"
    rows: list[dict[str, Any]] = []
    for result in standard_results:
        for case_metric in result.summary.combined_summary.per_case_metrics:
            rows.append(
                {
                    "evaluation_scope": "standard_hardened_grid",
                    "holdout_experiment": "",
                    "case_name": case_metric.case_name,
                    "feature_set": result.feature_set.name,
                    "detector_type": result.detector_type,
                    **_case_metrics_row(case_metric),
                }
            )
    for result in holdout_results:
        holdout = result.holdout_result
        for case_metric in holdout.summary.combined_summary.per_case_metrics:
            rows.append(
                {
                    "evaluation_scope": "supervised_holdout",
                    "holdout_experiment": holdout.experiment.name,
                    "case_name": case_metric.case_name,
                    "feature_set": result.feature_set.name,
                    "detector_type": holdout.detector_type,
                    **_case_metrics_row(case_metric),
                }
            )
    _write_csv(path, rows)
    return path


def _write_per_scenario_rates(
    output_dir: Path,
    standard_results: list[SupervisedAblationResult],
    holdout_results: list[SupervisedHoldoutAblationResult],
) -> Path:
    path = output_dir / "supervised_ablation_per_scenario_rates.csv"
    rows: list[dict[str, Any]] = []
    for result in standard_results:
        for rate in result.summary.combined_summary.per_scenario_rates:
            rows.append(
                {
                    "evaluation_scope": "standard_hardened_grid",
                    "holdout_experiment": "",
                    "feature_set": result.feature_set.name,
                    "detector_type": result.detector_type,
                    **_scenario_rate_row(rate),
                }
            )
    for result in holdout_results:
        holdout = result.holdout_result
        for rate in holdout.summary.combined_summary.per_scenario_rates:
            rows.append(
                {
                    "evaluation_scope": "supervised_holdout",
                    "holdout_experiment": holdout.experiment.name,
                    "feature_set": result.feature_set.name,
                    "detector_type": holdout.detector_type,
                    **_scenario_rate_row(rate),
                }
            )
    _write_csv(path, rows)
    return path


def _write_metadata(
    output_dir: Path,
    *,
    standard_results: list[SupervisedAblationResult],
    holdout_results: list[SupervisedHoldoutAblationResult],
    training_seeds: tuple[int, ...],
    evaluation_seeds: tuple[int, ...],
    holdout_evaluation_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "supervised_ablation_metadata.json"
    feature_sets = build_supervised_ablation_feature_sets()
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "training_seed_list": list(training_seeds),
        "standard_evaluation_seed_list": list(evaluation_seeds),
        "holdout_evaluation_seed_list": list(holdout_evaluation_seeds),
        "feature_sets": [asdict(feature_set) for feature_set in feature_sets],
        "standard_result_count": len(standard_results),
        "holdout_result_count": len(holdout_results),
        "outputs": [
            "supervised_ablation_summary.csv",
            "supervised_ablation_holdout_summary.csv",
            "supervised_ablation_per_case_metrics.csv",
            "supervised_ablation_per_scenario_rates.csv",
            "supervised_ablation_metadata.json",
        ],
        "holdout_experiments": sorted(
            {
                result.holdout_result.experiment.name
                for result in holdout_results
            }
        ),
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _metrics_row(summary: MultiSeedEvaluationSummary) -> dict[str, float | int]:
    metrics = summary.combined_summary.overall_metrics
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


def _scenario_rate_row(rate) -> dict[str, str | int | float]:
    return {
        "scenario_or_profile_name": rate.scenario_name,
        "total_flows": rate.total_flows,
        "true_beacon_flows": rate.true_beacon_flows,
        "predicted_beacon_flows": rate.predicted_beacon_flows,
        "rate": rate.detection_rate,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _without(features: tuple[str, ...], excluded: set[str]) -> tuple[str, ...]:
    return tuple(feature for feature in features if feature not in excluded)


def _unique_features(features: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for feature in features:
        if feature not in unique:
            unique.append(feature)
    return tuple(unique)
