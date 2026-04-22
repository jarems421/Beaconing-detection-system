from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection import SupervisedDetectorConfig

from .cache import FeatureCacheConfig
from .runner import (
    FROZEN_BASELINE_SEEDS,
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    MultiSeedEvaluationSummary,
    build_default_evaluation_grid,
    evaluate_supervised_detector_multi_seed,
)
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name
from .supervised_validation import (
    SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    SupervisedHoldoutResult,
    build_supervised_holdout_suite,
    evaluate_supervised_holdout_experiment,
)

RANDOM_FOREST_THRESHOLD_VALUES = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
RANDOM_FOREST_THRESHOLD_FEATURE_SETS = ("full", "timing_size")


@dataclass(frozen=True, slots=True)
class SupervisedThresholdSweepResult:
    feature_set: SupervisedFeatureSet
    threshold: float
    summary: MultiSeedEvaluationSummary


@dataclass(frozen=True, slots=True)
class SupervisedHoldoutThresholdSweepResult:
    feature_set: SupervisedFeatureSet
    threshold: float
    holdout_result: SupervisedHoldoutResult


def build_random_forest_threshold_feature_sets() -> list[SupervisedFeatureSet]:
    return [
        feature_set_by_name(name)
        for name in RANDOM_FOREST_THRESHOLD_FEATURE_SETS
    ]


def evaluate_random_forest_threshold_sweep(
    *,
    feature_sets: list[SupervisedFeatureSet] | None = None,
    thresholds: tuple[float, ...] = RANDOM_FOREST_THRESHOLD_VALUES,
    base_config: SupervisedDetectorConfig | None = None,
    cases: list[EvaluationCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[SupervisedThresholdSweepResult]:
    feature_sets = feature_sets or build_random_forest_threshold_feature_sets()
    base_config = base_config or SupervisedDetectorConfig()
    cases = cases or build_default_evaluation_grid()
    training_cases = training_cases or cases
    results: list[SupervisedThresholdSweepResult] = []
    for feature_set in feature_sets:
        for threshold in thresholds:
            config = replace(
                base_config,
                feature_names=feature_set.feature_names,
                prediction_threshold=threshold,
            )
            results.append(
                SupervisedThresholdSweepResult(
                    feature_set=feature_set,
                    threshold=threshold,
                    summary=evaluate_supervised_detector_multi_seed(
                        "random_forest",
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


def evaluate_random_forest_holdout_threshold_sweep(
    *,
    feature_sets: list[SupervisedFeatureSet] | None = None,
    thresholds: tuple[float, ...] = RANDOM_FOREST_THRESHOLD_VALUES,
    base_config: SupervisedDetectorConfig | None = None,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[SupervisedHoldoutThresholdSweepResult]:
    feature_sets = feature_sets or build_random_forest_threshold_feature_sets()
    experiments = build_supervised_holdout_suite()
    base_config = base_config or SupervisedDetectorConfig()
    results: list[SupervisedHoldoutThresholdSweepResult] = []
    for feature_set in feature_sets:
        for threshold in thresholds:
            config = replace(
                base_config,
                feature_names=feature_set.feature_names,
                prediction_threshold=threshold,
            )
            for experiment in experiments:
                results.append(
                    SupervisedHoldoutThresholdSweepResult(
                        feature_set=feature_set,
                        threshold=threshold,
                        holdout_result=evaluate_supervised_holdout_experiment(
                            experiment=experiment,
                            detector_type="random_forest",
                            config=config,
                            training_seeds=training_seeds,
                            evaluation_seeds=evaluation_seeds,
                            cache_config=cache_config,
                        ),
                    )
                )
    return results


def export_supervised_threshold_sweep_tables(
    *,
    output_dir: str | Path,
    standard_results: list[SupervisedThresholdSweepResult],
    holdout_results: list[SupervisedHoldoutThresholdSweepResult],
    thresholds: tuple[float, ...] = RANDOM_FOREST_THRESHOLD_VALUES,
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
        _write_profile_rates(output_path, standard_results, holdout_results),
        _write_metadata(
            output_path,
            standard_results=standard_results,
            holdout_results=holdout_results,
            thresholds=thresholds,
            training_seeds=training_seeds,
            evaluation_seeds=evaluation_seeds,
            holdout_evaluation_seeds=holdout_evaluation_seeds,
        ),
    ]
    return written_paths


def _write_standard_summary(
    output_dir: Path,
    results: list[SupervisedThresholdSweepResult],
) -> Path:
    path = output_dir / "supervised_threshold_sweep_summary.csv"
    rows = [
        {
            "evaluation_scope": "standard_hardened_grid",
            "feature_set": result.feature_set.name,
            "threshold": result.threshold,
            **_metrics_row(result.summary),
        }
        for result in results
    ]
    _write_csv(path, rows)
    return path


def _write_holdout_summary(
    output_dir: Path,
    results: list[SupervisedHoldoutThresholdSweepResult],
) -> Path:
    path = output_dir / "supervised_threshold_sweep_holdout_summary.csv"
    rows = []
    for result in results:
        holdout = result.holdout_result
        rows.append(
            {
                "evaluation_scope": "supervised_holdout",
                "holdout_experiment": holdout.experiment.name,
                "feature_set": result.feature_set.name,
                "threshold": result.threshold,
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
    standard_results: list[SupervisedThresholdSweepResult],
    holdout_results: list[SupervisedHoldoutThresholdSweepResult],
) -> Path:
    path = output_dir / "supervised_threshold_sweep_per_case_metrics.csv"
    rows: list[dict[str, Any]] = []
    for result in standard_results:
        for case_metric in result.summary.combined_summary.per_case_metrics:
            rows.append(
                {
                    "evaluation_scope": "standard_hardened_grid",
                    "holdout_experiment": "",
                    "case_name": case_metric.case_name,
                    "feature_set": result.feature_set.name,
                    "threshold": result.threshold,
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
                    "threshold": result.threshold,
                    **_case_metrics_row(case_metric),
                }
            )
    _write_csv(path, rows)
    return path


def _write_profile_rates(
    output_dir: Path,
    standard_results: list[SupervisedThresholdSweepResult],
    holdout_results: list[SupervisedHoldoutThresholdSweepResult],
) -> Path:
    path = output_dir / "supervised_threshold_sweep_profile_rates.csv"
    rows: list[dict[str, Any]] = []
    for result in standard_results:
        for rate in result.summary.combined_summary.per_scenario_rates:
            rows.append(
                {
                    "evaluation_scope": "standard_hardened_grid",
                    "holdout_experiment": "",
                    "feature_set": result.feature_set.name,
                    "threshold": result.threshold,
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
                    "threshold": result.threshold,
                    **_scenario_rate_row(rate),
                }
            )
    _write_csv(path, rows)
    return path


def _write_metadata(
    output_dir: Path,
    *,
    standard_results: list[SupervisedThresholdSweepResult],
    holdout_results: list[SupervisedHoldoutThresholdSweepResult],
    thresholds: tuple[float, ...],
    training_seeds: tuple[int, ...],
    evaluation_seeds: tuple[int, ...],
    holdout_evaluation_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "supervised_threshold_sweep_metadata.json"
    feature_sets = build_random_forest_threshold_feature_sets()
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "detector_type": "random_forest",
        "feature_sets": [asdict(feature_set) for feature_set in feature_sets],
        "thresholds": list(thresholds),
        "training_seed_list": list(training_seeds),
        "standard_evaluation_seed_list": list(evaluation_seeds),
        "holdout_evaluation_seed_list": list(holdout_evaluation_seeds),
        "standard_result_count": len(standard_results),
        "holdout_result_count": len(holdout_results),
        "outputs": [
            "supervised_threshold_sweep_summary.csv",
            "supervised_threshold_sweep_holdout_summary.csv",
            "supervised_threshold_sweep_per_case_metrics.csv",
            "supervised_threshold_sweep_profile_rates.csv",
            "supervised_threshold_sweep_metadata.json",
        ],
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
