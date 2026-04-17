from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from statistics import median
from typing import Any, Literal

from beacon_detector.data import (
    NormalTrafficProfile,
    ShortcutOverlapLevel,
    SyntheticTrafficConfig,
)
from beacon_detector.detection import (
    SupervisedDetectorConfig,
    detect_flow_feature_rows_supervised,
    fit_supervised_detector,
)
from beacon_detector.features import FlowFeatures

from .cache import FeatureCacheConfig, FEATURE_SCHEMA_VERSION
from .metrics import calculate_classification_metrics
from .runner import (
    EvaluationCase,
    FROZEN_BASELINE_SEEDS,
    MultiSeedEvaluationSummary,
    SUPERVISED_TRAINING_SEEDS,
    build_case_feature_rows,
    build_default_evaluation_grid,
    build_multiseed_evaluation_grid,
    build_supervised_training_features,
    evaluate_supervised_detector_multi_seed,
    summarize_metric_spread,
    summarize_prediction_records,
)
from .shortcut_stress import SHORTCUT_STRESS_SEEDS
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name
from .supervised_validation import (
    SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    build_supervised_holdout_suite,
)

DiagnosticScope = Literal[
    "standard_hardened_grid",
    "shortcut_stress",
    "supervised_holdout",
]
TrainingRegime = Literal["baseline_training", "stress_trained"]

RF_TIME_SIZE_DIAGNOSTIC_OPERATING_POINTS = (
    ("rf_full_threshold_0p6", "full", 0.6),
    ("rf_full_threshold_0p3", "full", 0.3),
)
RF_STRESS_TRAINING_OPERATING_POINTS = RF_TIME_SIZE_DIAGNOSTIC_OPERATING_POINTS
TIME_SIZE_DIAGNOSTIC_FEATURES = (
    "event_count",
    "flow_duration_seconds",
    "size_cv",
    "normalized_size_range",
    "size_bin_count",
    "dominant_size_bin_fraction",
    "near_median_size_fraction",
    "interarrival_iqr_seconds",
    "interarrival_mad_seconds",
    "gap_range_median_ratio",
    "interarrival_within_10pct_median_fraction",
    "interarrival_within_20pct_median_fraction",
    "interarrival_within_30pct_median_fraction",
    "dominant_interval_bin_fraction",
    "interval_bin_count",
    "adjacent_gap_similarity_fraction",
    "longest_similar_gap_run",
    "interarrival_median_absolute_percentage_deviation",
)


@dataclass(frozen=True, slots=True)
class DiagnosticFlowRecord:
    detector_name: str
    feature_set_name: str
    threshold: float
    evaluation_scope: DiagnosticScope
    holdout_experiment: str
    group_name: str
    case_name: str
    seed: int
    predicted_probability: float
    predicted_label: str
    true_label: str
    feature_values: dict[str, float | None]


@dataclass(frozen=True, slots=True)
class DiagnosticGroupSummary:
    detector_name: str
    feature_set_name: str
    threshold: float
    evaluation_scope: str
    group_name: str
    count: int
    mean_probability: float | None
    median_probability: float | None
    min_probability: float | None
    max_probability: float | None


@dataclass(frozen=True, slots=True)
class TimeSizeDiagnosticResult:
    flow_records: tuple[DiagnosticFlowRecord, ...]
    group_summaries: tuple[DiagnosticGroupSummary, ...]


@dataclass(frozen=True, slots=True)
class StressTrainingComparisonResult:
    detector_name: str
    feature_set: SupervisedFeatureSet
    threshold: float
    training_regime: TrainingRegime
    summary: MultiSeedEvaluationSummary


def build_stress_training_suite(
    start_time: datetime | None = None,
) -> list[EvaluationCase]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=950,
        normal_event_count=150,
        normal_flow_count=24,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=9,
        beacon_event_count=8,
        mean_interval_seconds=65.0,
        duration_seconds=5400,
        beacon_size_bytes=155,
        shortcut_overlap_level=ShortcutOverlapLevel.MEDIUM,
        normal_profiles=(
            NormalTrafficProfile.KEEPALIVE,
            NormalTrafficProfile.TELEMETRY,
            NormalTrafficProfile.API_POLLING,
            NormalTrafficProfile.BURSTY_SESSION,
            NormalTrafficProfile.SOFTWARE_UPDATE,
        ),
    )
    return [
        EvaluationCase(
            "stress_train_moderate_overlap_low_event",
            "Moderate overlap with low-event beacons included in training only.",
            replace(
                base,
                seed=950,
                beacon_event_count=6,
                time_size_jittered_event_count=6,
                time_size_jittered_jitter_fraction=0.70,
                time_size_jittered_size_jitter_fraction=0.70,
            ),
        ),
        EvaluationCase(
            "stress_train_moderate_time_size_jittered",
            "Moderate hard time+size jittered examples for training.",
            replace(
                base,
                seed=951,
                beacon_event_count=8,
                time_size_jittered_event_count=7,
                time_size_jittered_mean_interval_seconds=70.0,
                time_size_jittered_jitter_fraction=0.75,
                time_size_jittered_size_jitter_fraction=0.75,
            ),
        ),
        EvaluationCase(
            "stress_train_benign_overlap_mix",
            "Moderately overlapping benign profiles so stress training sees harder normal traffic.",
            replace(
                base,
                seed=952,
                normal_event_count=220,
                normal_flow_count=36,
                beacon_event_count=7,
                time_size_jittered_event_count=6,
                time_size_jittered_jitter_fraction=0.70,
                time_size_jittered_size_jitter_fraction=0.70,
            ),
        ),
    ]


def build_stress_eval_harder_suite(
    start_time: datetime | None = None,
) -> list[EvaluationCase]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=970,
        normal_event_count=190,
        normal_flow_count=32,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=8,
        beacon_event_count=6,
        mean_interval_seconds=72.0,
        duration_seconds=5400,
        beacon_size_bytes=175,
        shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
        normal_profiles=(
            NormalTrafficProfile.KEEPALIVE,
            NormalTrafficProfile.TELEMETRY,
            NormalTrafficProfile.API_POLLING,
            NormalTrafficProfile.BURSTY_SESSION,
            NormalTrafficProfile.SOFTWARE_UPDATE,
        ),
    )
    return [
        EvaluationCase(
            "stress_eval_harder_low_event_time_size",
            "Unseen harder low-event time+size jittered beacons with high overlap.",
            replace(
                base,
                seed=970,
                beacon_event_count=5,
                time_size_jittered_event_count=5,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
            ),
        ),
        EvaluationCase(
            "stress_eval_harder_size_duration_overlap",
            "Unseen high size and duration overlap with harder time+size jitter.",
            replace(
                base,
                seed=971,
                beacon_event_count=7,
                mean_interval_seconds=80.0,
                beacon_size_bytes=190,
                beacon_size_jitter_fraction=0.70,
                time_size_jittered_event_count=5,
                time_size_jittered_mean_interval_seconds=80.0,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
            ),
        ),
        EvaluationCase(
            "stress_eval_harder_benign_overlap_mix",
            "Unseen class-imbalanced high-overlap benign profile mix.",
            replace(
                base,
                seed=972,
                normal_event_count=300,
                normal_flow_count=48,
                beacon_event_count=5,
                time_size_jittered_event_count=5,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
            ),
        ),
    ]


def diagnostic_group_name(
    evaluation_scope: DiagnosticScope,
    predicted_label: str,
) -> str:
    outcome = "detected" if predicted_label == "beacon" else "missed"
    if evaluation_scope == "standard_hardened_grid":
        return f"{outcome}_standard_time_size_jittered"
    if evaluation_scope == "shortcut_stress":
        return f"{outcome}_shortcut_time_size_jittered"
    return f"{outcome}_holdout_time_size_jittered"


def run_rf_time_size_jittered_diagnostic(
    *,
    standard_cases: list[EvaluationCase] | None = None,
    shortcut_stress_cases: list[EvaluationCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    standard_seeds: tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    shortcut_stress_seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    holdout_evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> TimeSizeDiagnosticResult:
    standard_cases = standard_cases or build_default_evaluation_grid()
    training_cases = training_cases or standard_cases
    shortcut_stress_cases = shortcut_stress_cases or build_stress_eval_harder_suite()

    records: list[DiagnosticFlowRecord] = []
    for detector_name, feature_set_name, threshold in RF_TIME_SIZE_DIAGNOSTIC_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        model = _fit_rf_model(
            config=config,
            training_cases=training_cases,
            training_seeds=training_seeds,
            cache_config=cache_config,
        )
        records.extend(
            _collect_time_size_records(
                detector_name=detector_name,
                feature_set_name=feature_set.name,
                threshold=threshold,
                evaluation_scope="standard_hardened_grid",
                holdout_experiment="",
                model=model,
                cases=standard_cases,
                seeds=standard_seeds,
                cache_config=cache_config,
            )
        )
        records.extend(
            _collect_time_size_records(
                detector_name=detector_name,
                feature_set_name=feature_set.name,
                threshold=threshold,
                evaluation_scope="shortcut_stress",
                holdout_experiment="",
                model=model,
                cases=shortcut_stress_cases,
                seeds=shortcut_stress_seeds,
                cache_config=cache_config,
            )
        )
        records.extend(
            _collect_holdout_time_size_records(
                detector_name=detector_name,
                feature_set=feature_set,
                threshold=threshold,
                config=config,
                training_seeds=training_seeds,
                evaluation_seeds=holdout_evaluation_seeds,
                cache_config=cache_config,
            )
        )

    return TimeSizeDiagnosticResult(
        flow_records=tuple(records),
        group_summaries=tuple(_summarize_diagnostic_groups(records)),
    )


def run_stress_trained_rf_experiment(
    *,
    baseline_training_cases: list[EvaluationCase] | None = None,
    stress_training_cases: list[EvaluationCase] | None = None,
    stress_eval_cases: list[EvaluationCase] | None = None,
    evaluation_seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[StressTrainingComparisonResult]:
    baseline_training_cases = baseline_training_cases or build_default_evaluation_grid()
    stress_training_cases = stress_training_cases or build_stress_training_suite()
    stress_eval_cases = stress_eval_cases or build_stress_eval_harder_suite()
    stress_augmented_training_cases = baseline_training_cases + stress_training_cases

    results: list[StressTrainingComparisonResult] = []
    for detector_name, feature_set_name, threshold in RF_STRESS_TRAINING_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        for training_regime, training_cases in (
            ("baseline_training", baseline_training_cases),
            ("stress_trained", stress_augmented_training_cases),
        ):
            name = f"{detector_name}_{training_regime}"
            results.append(
                StressTrainingComparisonResult(
                    detector_name=name,
                    feature_set=feature_set,
                    threshold=threshold,
                    training_regime=training_regime,  # type: ignore[arg-type]
                    summary=evaluate_supervised_detector_multi_seed(
                        "random_forest",
                        seeds=evaluation_seeds,
                        config=config,
                        cases=stress_eval_cases,
                        training_seeds=training_seeds,
                        training_cases=training_cases,
                        cache_config=cache_config,
                    ),
                )
            )
    return results


def export_rf_diagnostic_tables(
    *,
    output_dir: str | Path,
    diagnostic: TimeSizeDiagnosticResult,
    stress_results: list[StressTrainingComparisonResult],
    stress_training_cases: list[EvaluationCase],
    stress_eval_cases: list[EvaluationCase],
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = SHORTCUT_STRESS_SEEDS,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return [
        _write_diagnostic_summary(output_path, diagnostic),
        _write_group_comparison(output_path, diagnostic),
        _write_false_negative_samples(output_path, diagnostic),
        _write_stress_training_comparison(output_path, stress_results),
        _write_profile_rates(output_path, stress_results),
        _write_metadata(
            output_path,
            stress_training_cases=stress_training_cases,
            stress_eval_cases=stress_eval_cases,
            training_seeds=training_seeds,
            evaluation_seeds=evaluation_seeds,
        ),
    ]


def _fit_rf_model(
    *,
    config: SupervisedDetectorConfig,
    training_cases: list[EvaluationCase],
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
):
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        training_cases=training_cases,
        cache_config=cache_config,
    )
    return fit_supervised_detector(
        training_features,
        detector_type="random_forest",
        config=config,
    )


def _collect_time_size_records(
    *,
    detector_name: str,
    feature_set_name: str,
    threshold: float,
    evaluation_scope: DiagnosticScope,
    holdout_experiment: str,
    model,
    cases: list[EvaluationCase],
    seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[DiagnosticFlowRecord]:
    records: list[DiagnosticFlowRecord] = []
    for seed_cases in build_multiseed_evaluation_grid(seeds, template_cases=cases):
        for case in seed_cases:
            feature_rows = [
                row
                for row in build_case_feature_rows(case, cache_config=cache_config)
                if row.scenario_name == "time_size_jittered"
            ]
            results = detect_flow_feature_rows_supervised(feature_rows, model=model)
            for features, result in zip(feature_rows, results):
                records.append(
                    DiagnosticFlowRecord(
                        detector_name=detector_name,
                        feature_set_name=feature_set_name,
                        threshold=threshold,
                        evaluation_scope=evaluation_scope,
                        holdout_experiment=holdout_experiment,
                        group_name=diagnostic_group_name(
                            evaluation_scope,
                            result.predicted_label,
                        ),
                        case_name=case.name,
                        seed=case.config.seed,
                        predicted_probability=result.score,
                        predicted_label=result.predicted_label,
                        true_label=result.true_label,
                        feature_values=_selected_feature_values(features),
                    )
                )
    return records


def _collect_holdout_time_size_records(
    *,
    detector_name: str,
    feature_set: SupervisedFeatureSet,
    threshold: float,
    config: SupervisedDetectorConfig,
    training_seeds: tuple[int, ...],
    evaluation_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[DiagnosticFlowRecord]:
    records: list[DiagnosticFlowRecord] = []
    for experiment in build_supervised_holdout_suite():
        if experiment.name != "time_size_jittered_scenario_holdout":
            continue
        training_features = build_supervised_training_features(
            training_seeds=training_seeds,
            training_cases=list(experiment.training_cases),
            cache_config=cache_config,
        )
        filtered_training = [
            row
            for row in training_features
            if (row.scenario_name or "") not in experiment.excluded_training_scenarios
            and (row.scenario_name or "") not in experiment.excluded_training_profiles
        ]
        model = fit_supervised_detector(
            filtered_training,
            detector_type="random_forest",
            config=config,
        )
        records.extend(
            _collect_time_size_records(
                detector_name=detector_name,
                feature_set_name=feature_set.name,
                threshold=threshold,
                evaluation_scope="supervised_holdout",
                holdout_experiment=experiment.name,
                model=model,
                cases=list(experiment.evaluation_cases),
                seeds=evaluation_seeds,
                cache_config=cache_config,
            )
        )
    return records


def _selected_feature_values(features: FlowFeatures) -> dict[str, float | None]:
    values: dict[str, float | None] = {}
    for feature_name in TIME_SIZE_DIAGNOSTIC_FEATURES:
        value = getattr(features, feature_name)
        values[feature_name] = None if value is None else float(value)
    return values


def _summarize_diagnostic_groups(
    records: list[DiagnosticFlowRecord],
) -> list[DiagnosticGroupSummary]:
    keys = sorted(
        {
            (
                record.detector_name,
                record.feature_set_name,
                record.threshold,
                record.evaluation_scope,
                record.group_name,
            )
            for record in records
        }
    )
    summaries: list[DiagnosticGroupSummary] = []
    for detector_name, feature_set_name, threshold, evaluation_scope, group_name in keys:
        group_records = [
            record
            for record in records
            if record.detector_name == detector_name
            and record.feature_set_name == feature_set_name
            and record.threshold == threshold
            and record.evaluation_scope == evaluation_scope
            and record.group_name == group_name
        ]
        probabilities = [record.predicted_probability for record in group_records]
        summaries.append(
            DiagnosticGroupSummary(
                detector_name=detector_name,
                feature_set_name=feature_set_name,
                threshold=threshold,
                evaluation_scope=evaluation_scope,
                group_name=group_name,
                count=len(group_records),
                mean_probability=_mean(probabilities),
                median_probability=_median(probabilities),
                min_probability=min(probabilities) if probabilities else None,
                max_probability=max(probabilities) if probabilities else None,
            )
        )
    return summaries


def _write_diagnostic_summary(
    output_dir: Path,
    diagnostic: TimeSizeDiagnosticResult,
) -> Path:
    path = output_dir / "rf_time_size_jittered_diagnostic_summary.csv"
    rows = [
        {
            "detector_name": summary.detector_name,
            "feature_set": summary.feature_set_name,
            "threshold": summary.threshold,
            "evaluation_scope": summary.evaluation_scope,
            "group_name": summary.group_name,
            "count": summary.count,
            "mean_probability": summary.mean_probability,
            "median_probability": summary.median_probability,
            "min_probability": summary.min_probability,
            "max_probability": summary.max_probability,
        }
        for summary in diagnostic.group_summaries
    ]
    _write_csv(path, rows)
    return path


def _write_group_comparison(
    output_dir: Path,
    diagnostic: TimeSizeDiagnosticResult,
) -> Path:
    path = output_dir / "rf_time_size_jittered_group_comparison.csv"
    rows: list[dict[str, Any]] = []
    group_keys = sorted(
        {
            (
                record.detector_name,
                record.feature_set_name,
                record.threshold,
                record.evaluation_scope,
                record.group_name,
            )
            for record in diagnostic.flow_records
        }
    )
    for detector_name, feature_set_name, threshold, evaluation_scope, group_name in group_keys:
        group_records = [
            record
            for record in diagnostic.flow_records
            if record.detector_name == detector_name
            and record.feature_set_name == feature_set_name
            and record.threshold == threshold
            and record.evaluation_scope == evaluation_scope
            and record.group_name == group_name
        ]
        for feature_name in TIME_SIZE_DIAGNOSTIC_FEATURES:
            values = [
                record.feature_values[feature_name]
                for record in group_records
                if record.feature_values[feature_name] is not None
            ]
            rows.append(
                {
                    "detector_name": detector_name,
                    "feature_set": feature_set_name,
                    "threshold": threshold,
                    "evaluation_scope": evaluation_scope,
                    "group_name": group_name,
                    "feature_name": feature_name,
                    "count": len(values),
                    "mean": _mean(values),
                    "median": _median(values),
                    "min": min(values) if values else None,
                    "max": max(values) if values else None,
                }
            )
    _write_csv(path, rows)
    return path


def _write_false_negative_samples(
    output_dir: Path,
    diagnostic: TimeSizeDiagnosticResult,
) -> Path:
    path = output_dir / "rf_time_size_jittered_false_negative_samples.csv"
    rows: list[dict[str, Any]] = []
    false_negatives = [
        record
        for record in diagnostic.flow_records
        if record.true_label == "beacon" and record.predicted_label == "benign"
    ]
    for record in sorted(false_negatives, key=lambda item: item.predicted_probability)[:100]:
        rows.append(
            {
                "detector_name": record.detector_name,
                "feature_set": record.feature_set_name,
                "threshold": record.threshold,
                "evaluation_scope": record.evaluation_scope,
                "holdout_experiment": record.holdout_experiment,
                "group_name": record.group_name,
                "case_name": record.case_name,
                "seed": record.seed,
                "predicted_probability": record.predicted_probability,
                "predicted_label": record.predicted_label,
                "true_label": record.true_label,
                **record.feature_values,
            }
        )
    _write_csv(path, rows)
    return path


def _write_stress_training_comparison(
    output_dir: Path,
    results: list[StressTrainingComparisonResult],
) -> Path:
    path = output_dir / "rf_stress_training_comparison.csv"
    rows = []
    for result in results:
        metrics = result.summary.combined_summary.overall_metrics
        matrix = metrics.confusion_matrix
        rows.append(
            {
                "detector_name": result.detector_name,
                "feature_set": result.feature_set.name,
                "threshold": result.threshold,
                "training_regime": result.training_regime,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1_score,
                "false_positive_rate": metrics.false_positive_rate,
                "tp": matrix.true_positive,
                "fp": matrix.false_positive,
                "tn": matrix.true_negative,
                "fn": matrix.false_negative,
            }
        )
    _write_csv(path, rows)
    return path


def _write_profile_rates(
    output_dir: Path,
    results: list[StressTrainingComparisonResult],
) -> Path:
    path = output_dir / "rf_stress_training_profile_rates.csv"
    rows = []
    for result in results:
        for rate in result.summary.combined_summary.per_scenario_rates:
            rows.append(
                {
                    "detector_name": result.detector_name,
                    "feature_set": result.feature_set.name,
                    "threshold": result.threshold,
                    "training_regime": result.training_regime,
                    "scenario_or_profile_name": rate.scenario_name,
                    "category": "benign_profile" if rate.true_beacon_flows == 0 else "beacon",
                    "rate_type": "false_flag_rate" if rate.true_beacon_flows == 0 else "detection_rate",
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
    stress_training_cases: list[EvaluationCase],
    stress_eval_cases: list[EvaluationCase],
    training_seeds: tuple[int, ...],
    evaluation_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "diagnostic_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "purpose": (
            "Diagnose RF misses on hard time_size_jittered flows and test "
            "whether stress examples in training improve unseen hard-stress generalization."
        ),
        "diagnostic_operating_points": [
            {"detector_name": name, "feature_set": feature_set, "threshold": threshold}
            for name, feature_set, threshold in RF_TIME_SIZE_DIAGNOSTIC_OPERATING_POINTS
        ],
        "stress_training_case_names": [case.name for case in stress_training_cases],
        "stress_eval_case_names": [case.name for case in stress_eval_cases],
        "stress_training_difficulty": [_case_difficulty_row(case) for case in stress_training_cases],
        "stress_eval_difficulty": [_case_difficulty_row(case) for case in stress_eval_cases],
        "training_seed_list": list(training_seeds),
        "evaluation_seed_list": list(evaluation_seeds),
        "outputs": [
            "rf_time_size_jittered_diagnostic_summary.csv",
            "rf_time_size_jittered_group_comparison.csv",
            "rf_time_size_jittered_false_negative_samples.csv",
            "rf_stress_training_comparison.csv",
            "rf_stress_training_profile_rates.csv",
            "diagnostic_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _case_difficulty_row(case: EvaluationCase) -> dict[str, Any]:
    return {
        "case_name": case.name,
        "shortcut_overlap_level": ShortcutOverlapLevel(
            case.config.shortcut_overlap_level
        ).value,
        "beacon_event_count": case.config.beacon_event_count,
        "time_size_jittered_event_count": case.config.time_size_jittered_event_count,
        "time_size_jittered_jitter_fraction": case.config.time_size_jittered_jitter_fraction,
        "time_size_jittered_size_jitter_fraction": case.config.time_size_jittered_size_jitter_fraction,
    }


def _mean(values: list[float | None]) -> float | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    return sum(clean) / len(clean)


def _median(values: list[float | None]) -> float | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    return float(median(clean))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
