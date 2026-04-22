from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection import SupervisedDetectorConfig

from .cache import FEATURE_SCHEMA_VERSION, FeatureCacheConfig
from .runner import (
    FROZEN_BASELINE_SEEDS,
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    MultiSeedEvaluationSummary,
    build_default_evaluation_grid,
    evaluate_supervised_detector_multi_seed,
)
from .shortcut_stress import SHORTCUT_STRESS_SEEDS, build_shortcut_stress_suite
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name
from .supervised_validation import (
    SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    SupervisedHoldoutResult,
    build_supervised_holdout_suite,
    evaluate_supervised_holdout_experiment,
)

FEATURE_IMPROVEMENT_RF_OPERATING_POINTS = (
    ("rf_full_threshold_0p6", "full", 0.6),
    ("rf_full_threshold_0p3", "full", 0.3),
    ("rf_timing_size_threshold_0p4", "timing_size", 0.4),
)


@dataclass(frozen=True, slots=True)
class FeatureImprovementStandardResult:
    detector_name: str
    feature_set: SupervisedFeatureSet
    threshold: float
    summary: MultiSeedEvaluationSummary


@dataclass(frozen=True, slots=True)
class FeatureImprovementHoldoutResult:
    detector_name: str
    feature_set: SupervisedFeatureSet
    threshold: float
    holdout_result: SupervisedHoldoutResult


@dataclass(frozen=True, slots=True)
class FeatureImprovementEvaluation:
    standard_results: tuple[FeatureImprovementStandardResult, ...]
    holdout_results: tuple[FeatureImprovementHoldoutResult, ...]
    shortcut_stress_results: tuple[FeatureImprovementStandardResult, ...]


def run_feature_improvement_evaluation(
    *,
    standard_cases: list[EvaluationCase] | None = None,
    shortcut_stress_cases: list[EvaluationCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    standard_seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    holdout_evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    shortcut_stress_seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> FeatureImprovementEvaluation:
    standard_cases = standard_cases or build_default_evaluation_grid()
    training_cases = training_cases or standard_cases
    shortcut_stress_cases = shortcut_stress_cases or build_shortcut_stress_suite()

    return FeatureImprovementEvaluation(
        standard_results=tuple(
            _evaluate_standard_scope(
                cases=standard_cases,
                training_cases=training_cases,
                seeds=standard_seeds,
                training_seeds=training_seeds,
                cache_config=cache_config,
            )
        ),
        holdout_results=tuple(
            _evaluate_holdout_scope(
                training_seeds=training_seeds,
                evaluation_seeds=holdout_evaluation_seeds,
                cache_config=cache_config,
            )
        ),
        shortcut_stress_results=tuple(
            _evaluate_standard_scope(
                cases=shortcut_stress_cases,
                training_cases=training_cases,
                seeds=shortcut_stress_seeds,
                training_seeds=training_seeds,
                cache_config=cache_config,
            )
        ),
    )


def export_feature_improvement_tables(
    *,
    output_dir: str | Path,
    evaluation: FeatureImprovementEvaluation,
    standard_cases: list[EvaluationCase],
    shortcut_stress_cases: list[EvaluationCase],
    standard_seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    holdout_evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    shortcut_stress_seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return [
        _write_standard_summary(output_path, evaluation.standard_results),
        _write_holdout_summary(output_path, evaluation.holdout_results),
        _write_shortcut_summary(output_path, evaluation.shortcut_stress_results),
        _write_profile_rates(output_path, evaluation),
        _write_metadata(
            output_path,
            evaluation=evaluation,
            standard_cases=standard_cases,
            shortcut_stress_cases=shortcut_stress_cases,
            standard_seeds=standard_seeds,
            holdout_evaluation_seeds=holdout_evaluation_seeds,
            shortcut_stress_seeds=shortcut_stress_seeds,
            training_seeds=training_seeds,
        ),
    ]


def _evaluate_standard_scope(
    *,
    cases: list[EvaluationCase],
    training_cases: list[EvaluationCase],
    seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[FeatureImprovementStandardResult]:
    results: list[FeatureImprovementStandardResult] = []
    for detector_name, feature_set_name, threshold in FEATURE_IMPROVEMENT_RF_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        results.append(
            FeatureImprovementStandardResult(
                detector_name=detector_name,
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


def _evaluate_holdout_scope(
    *,
    training_seeds: tuple[int, ...],
    evaluation_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[FeatureImprovementHoldoutResult]:
    results: list[FeatureImprovementHoldoutResult] = []
    for detector_name, feature_set_name, threshold in FEATURE_IMPROVEMENT_RF_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        for experiment in build_supervised_holdout_suite():
            results.append(
                FeatureImprovementHoldoutResult(
                    detector_name=detector_name,
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


def _write_standard_summary(
    output_dir: Path,
    results: tuple[FeatureImprovementStandardResult, ...],
) -> Path:
    path = output_dir / "feature_improvement_summary.csv"
    rows = [
        {
            "evaluation_scope": "standard_hardened_grid",
            "detector_name": result.detector_name,
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
    results: tuple[FeatureImprovementHoldoutResult, ...],
) -> Path:
    path = output_dir / "feature_improvement_holdout_summary.csv"
    rows = []
    for result in results:
        holdout = result.holdout_result
        rows.append(
            {
                "evaluation_scope": "supervised_holdout",
                "holdout_experiment": holdout.experiment.name,
                "detector_name": result.detector_name,
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


def _write_shortcut_summary(
    output_dir: Path,
    results: tuple[FeatureImprovementStandardResult, ...],
) -> Path:
    path = output_dir / "feature_improvement_shortcut_stress_summary.csv"
    rows = [
        {
            "evaluation_scope": "shortcut_stress",
            "detector_name": result.detector_name,
            "feature_set": result.feature_set.name,
            "threshold": result.threshold,
            **_metrics_row(result.summary),
        }
        for result in results
    ]
    _write_csv(path, rows)
    return path


def _write_profile_rates(
    output_dir: Path,
    evaluation: FeatureImprovementEvaluation,
) -> Path:
    path = output_dir / "feature_improvement_profile_rates.csv"
    rows: list[dict[str, Any]] = []
    for result in evaluation.standard_results:
        rows.extend(_profile_rows("standard_hardened_grid", "", result))
    for result in evaluation.shortcut_stress_results:
        rows.extend(_profile_rows("shortcut_stress", "", result))
    for result in evaluation.holdout_results:
        holdout = result.holdout_result
        rows.extend(
            _profile_rows(
                "supervised_holdout",
                holdout.experiment.name,
                result,
                holdout.summary,
            )
        )
    _write_csv(path, rows)
    return path


def _write_metadata(
    output_dir: Path,
    *,
    evaluation: FeatureImprovementEvaluation,
    standard_cases: list[EvaluationCase],
    shortcut_stress_cases: list[EvaluationCase],
    standard_seeds: tuple[int, ...],
    holdout_evaluation_seeds: tuple[int, ...],
    shortcut_stress_seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "feature_improvement_metadata.json"
    feature_sets = {
        result.feature_set.name: asdict(result.feature_set)
        for result in (
            list(evaluation.standard_results)
            + list(evaluation.shortcut_stress_results)
        )
    }
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "purpose": (
            "Evaluate targeted behavioural feature additions for low-event, "
            "high-jitter, size-overlapping beaconing."
        ),
        "operating_points": [
            {
                "detector_name": detector_name,
                "feature_set": feature_set_name,
                "threshold": threshold,
            }
            for detector_name, feature_set_name, threshold in (
                FEATURE_IMPROVEMENT_RF_OPERATING_POINTS
            )
        ],
        "feature_sets": list(feature_sets.values()),
        "standard_case_names": [case.name for case in standard_cases],
        "shortcut_stress_case_names": [case.name for case in shortcut_stress_cases],
        "training_seed_list": list(training_seeds),
        "standard_evaluation_seed_list": list(standard_seeds),
        "holdout_evaluation_seed_list": list(holdout_evaluation_seeds),
        "shortcut_stress_seed_list": list(shortcut_stress_seeds),
        "outputs": [
            "feature_improvement_summary.csv",
            "feature_improvement_holdout_summary.csv",
            "feature_improvement_shortcut_stress_summary.csv",
            "feature_improvement_profile_rates.csv",
            "feature_improvement_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _profile_rows(
    evaluation_scope: str,
    holdout_experiment: str,
    result,
    summary: MultiSeedEvaluationSummary | None = None,
) -> list[dict[str, Any]]:
    summary = summary or result.summary
    rows: list[dict[str, Any]] = []
    for rate in summary.combined_summary.per_scenario_rates:
        rows.append(
            {
                "evaluation_scope": evaluation_scope,
                "holdout_experiment": holdout_experiment,
                "detector_name": result.detector_name,
                "feature_set": result.feature_set.name,
                "threshold": result.threshold,
                "scenario_or_profile_name": rate.scenario_name,
                "category": "benign_profile" if rate.true_beacon_flows == 0 else "beacon",
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
    return rows


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


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
