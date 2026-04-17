from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from beacon_detector.detection import (
    ISOLATION_FOREST_NAME,
    LOCAL_OUTLIER_FACTOR_NAME,
    LOGISTIC_REGRESSION_NAME,
    RANDOM_FOREST_NAME,
    AnomalyDetectorConfig,
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    STATISTICAL_BASELINE_NAME,
    StatisticalBaselineConfig,
    SupervisedDetectorConfig,
)

from .runner import (
    EvaluationCase,
    FROZEN_BASELINE_SEEDS,
    MultiSeedEvaluationSummary,
    MultiSeedThresholdResult,
)


def export_experiment_tables(
    *,
    output_dir: str | Path = "results/tables",
    baseline_summaries: dict[str, MultiSeedEvaluationSummary],
    threshold_results: list[MultiSeedThresholdResult],
    cases: list[EvaluationCase],
    seeds: tuple[int, ...] | list[int] = FROZEN_BASELINE_SEEDS,
    rule_operating_threshold: float = 2.8,
    statistical_config: StatisticalBaselineConfig | None = None,
    anomaly_config: AnomalyDetectorConfig | None = None,
    supervised_config: SupervisedDetectorConfig | None = None,
    detector_operating_points: dict[str, str] | None = None,
    additional_metadata: dict[str, Any] | None = None,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    statistical_config = statistical_config or StatisticalBaselineConfig()
    anomaly_config = anomaly_config or AnomalyDetectorConfig()
    supervised_config = supervised_config or SupervisedDetectorConfig()
    operating_points = _build_operating_points(
        detector_names=tuple(baseline_summaries.keys()),
        rule_operating_threshold=rule_operating_threshold,
        statistical_config=statistical_config,
        anomaly_config=anomaly_config,
        supervised_config=supervised_config,
    )
    if detector_operating_points:
        operating_points.update(detector_operating_points)

    written_paths = [
        _write_baseline_comparison(output_path, baseline_summaries, operating_points),
        _write_per_case_metrics(output_path, baseline_summaries),
        _write_per_scenario_profile_rates(output_path, baseline_summaries),
        _write_failure_summary(output_path, baseline_summaries, failure_type="false_positive"),
        _write_failure_summary(output_path, baseline_summaries, failure_type="false_negative"),
        _write_threshold_comparison(output_path, threshold_results),
        _write_experiment_metadata(
            output_path,
            cases=cases,
            seeds=tuple(seeds),
            detector_names=tuple(baseline_summaries.keys()),
            rule_operating_threshold=rule_operating_threshold,
            threshold_results=threshold_results,
            statistical_config=statistical_config,
            anomaly_config=anomaly_config,
            supervised_config=supervised_config,
            operating_points=operating_points,
            additional_metadata=additional_metadata or {},
        ),
    ]
    return written_paths


def _write_baseline_comparison(
    output_dir: Path,
    baseline_summaries: dict[str, MultiSeedEvaluationSummary],
    operating_points: dict[str, str],
) -> Path:
    path = output_dir / "baseline_comparison.csv"
    rows: list[dict[str, Any]] = []
    for detector_name, summary in baseline_summaries.items():
        metrics = summary.combined_summary.overall_metrics
        matrix = metrics.confusion_matrix
        spread = summary.metric_spread
        rows.append(
            {
                "detector_name": detector_name,
                "operating_point": operating_points.get(detector_name, "default"),
                "mean_precision": spread.mean_precision,
                "mean_recall": spread.mean_recall,
                "mean_f1": spread.mean_f1_score,
                "mean_false_positive_rate": spread.mean_false_positive_rate,
                "combined_tp": matrix.true_positive,
                "combined_fp": matrix.false_positive,
                "combined_tn": matrix.true_negative,
                "combined_fn": matrix.false_negative,
            }
        )
    _write_csv(path, rows)
    return path


def _write_per_case_metrics(
    output_dir: Path,
    baseline_summaries: dict[str, MultiSeedEvaluationSummary],
) -> Path:
    path = output_dir / "per_case_metrics.csv"
    rows: list[dict[str, Any]] = []
    for detector_name, summary in baseline_summaries.items():
        for case_metric in summary.combined_summary.per_case_metrics:
            metrics = case_metric.metrics
            matrix = metrics.confusion_matrix
            rows.append(
                {
                    "detector_name": detector_name,
                    "case_name": case_metric.case_name,
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


def _write_per_scenario_profile_rates(
    output_dir: Path,
    baseline_summaries: dict[str, MultiSeedEvaluationSummary],
) -> Path:
    path = output_dir / "per_scenario_profile_rates.csv"
    rows: list[dict[str, Any]] = []
    for detector_name, summary in baseline_summaries.items():
        for rate in summary.combined_summary.per_scenario_rates:
            is_beacon = rate.true_beacon_flows > 0
            rows.append(
                {
                    "detector_name": detector_name,
                    "scenario_or_profile_name": rate.scenario_name,
                    "category": "beacon" if is_beacon else "benign_profile",
                    "rate_type": "detection_rate" if is_beacon else "false_flag_rate",
                    "rate": rate.detection_rate,
                    "total_flows": rate.total_flows,
                    "true_beacon_flows": rate.true_beacon_flows,
                    "predicted_beacon_flows": rate.predicted_beacon_flows,
                }
            )
    _write_csv(path, rows)
    return path


def _write_failure_summary(
    output_dir: Path,
    baseline_summaries: dict[str, MultiSeedEvaluationSummary],
    failure_type: str,
) -> Path:
    path = output_dir / f"{failure_type}_summary.csv"
    fieldnames = [
        "detector_name",
        "case_name",
        "seed",
        "scenario_name",
        "event_count",
        "score",
        "predicted_label",
        "true_label",
        "triggered_reasons",
        "top_contributors",
        "top_standardized_feature_deviations",
    ]
    rows: list[dict[str, Any]] = []
    for detector_name, summary in baseline_summaries.items():
        for record in summary.combined_summary.failure_records:
            is_false_positive = (
                record.true_label != "beacon" and record.predicted_label == "beacon"
            )
            is_false_negative = (
                record.true_label == "beacon" and record.predicted_label != "beacon"
            )
            if failure_type == "false_positive" and not is_false_positive:
                continue
            if failure_type == "false_negative" and not is_false_negative:
                continue

            contributors = ";".join(record.triggered_rules)
            rows.append(
                {
                    "detector_name": detector_name,
                    "case_name": record.case_name,
                    "seed": record.seed,
                    "scenario_name": record.scenario_name or "unknown",
                    "event_count": record.event_count,
                    "score": record.score,
                    "predicted_label": record.predicted_label,
                    "true_label": record.true_label,
                    "triggered_reasons": contributors,
                    "top_contributors": contributors,
                    "top_standardized_feature_deviations": (
                        contributors if _is_anomaly_detector_name(detector_name) else ""
                    ),
                }
            )
    _write_csv(path, rows, fieldnames=fieldnames)
    return path


def _write_threshold_comparison(
    output_dir: Path,
    threshold_results: list[MultiSeedThresholdResult],
) -> Path:
    path = output_dir / "threshold_comparison.csv"
    rows: list[dict[str, Any]] = []
    for result in threshold_results:
        spread = result.summary.metric_spread
        rows.append(
            {
                "threshold": result.prediction_threshold,
                "detector_name": FROZEN_RULE_BASELINE_NAME,
                "mean_precision": spread.mean_precision,
                "mean_recall": spread.mean_recall,
                "mean_f1": spread.mean_f1_score,
                "mean_false_positive_rate": spread.mean_false_positive_rate,
            }
        )
    _write_csv(path, rows)
    return path


def _write_experiment_metadata(
    output_dir: Path,
    *,
    cases: list[EvaluationCase],
    seeds: tuple[int, ...],
    detector_names: tuple[str, ...],
    rule_operating_threshold: float,
    threshold_results: list[MultiSeedThresholdResult],
    statistical_config: StatisticalBaselineConfig,
    anomaly_config: AnomalyDetectorConfig,
    supervised_config: SupervisedDetectorConfig,
    operating_points: dict[str, str],
    additional_metadata: dict[str, Any],
) -> Path:
    path = output_dir / "experiment_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "seed_list": list(seeds),
        "hardened_grid_case_names": [case.name for case in cases],
        "detector_names": list(detector_names),
        "operating_points": operating_points,
        "rule_baseline": {
            "name": FROZEN_RULE_BASELINE_NAME,
            "operating_threshold": rule_operating_threshold,
            "threshold_comparison_values": [
                result.prediction_threshold for result in threshold_results
            ],
            "thresholds": asdict(FROZEN_RULE_BASELINE_THRESHOLDS),
        },
        "statistical_baseline": {
            "name": STATISTICAL_BASELINE_NAME,
            "config": asdict(statistical_config),
        },
        "anomaly_detection": {
            "detector_names": [
                name for name in detector_names
                if _is_anomaly_detector_name(name)
            ],
            "config": asdict(anomaly_config),
        },
        "supervised_detection": {
            "detector_names": [
                name for name in detector_names
                if _is_supervised_detector_name(name)
            ],
            "config": asdict(supervised_config),
        },
        "additional_metadata": additional_metadata,
        "outputs": [
            "baseline_comparison.csv",
            "per_case_metrics.csv",
            "per_scenario_profile_rates.csv",
            "false_positive_summary.csv",
            "false_negative_summary.csv",
            "threshold_comparison.csv",
            "experiment_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str] | None = None,
) -> None:
    fieldnames = fieldnames or (list(rows[0].keys()) if rows else [])

    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _build_operating_points(
    *,
    detector_names: tuple[str, ...],
    rule_operating_threshold: float,
    statistical_config: StatisticalBaselineConfig,
    anomaly_config: AnomalyDetectorConfig,
    supervised_config: SupervisedDetectorConfig,
) -> dict[str, str]:
    operating_points: dict[str, str] = {}
    for detector_name in detector_names:
        if detector_name == FROZEN_RULE_BASELINE_NAME:
            operating_points[detector_name] = (
                f"threshold={rule_operating_threshold:g}"
            )
        elif detector_name == STATISTICAL_BASELINE_NAME:
            operating_points[detector_name] = (
                f"benign_score_quantile={statistical_config.benign_score_quantile:g}"
            )
        elif detector_name in {ISOLATION_FOREST_NAME, LOCAL_OUTLIER_FACTOR_NAME}:
            operating_points[detector_name] = (
                f"contamination={anomaly_config.contamination:g}"
            )
        elif _is_anomaly_detector_name(detector_name):
            operating_points[detector_name] = (
                f"contamination={anomaly_config.contamination:g}"
            )
        elif _is_supervised_detector_name(detector_name):
            operating_points[detector_name] = (
                f"threshold={supervised_config.prediction_threshold:g};"
                f"features={len(supervised_config.feature_names)}"
            )
        else:
            operating_points[detector_name] = "default"
    return operating_points


def _is_anomaly_detector_name(detector_name: str) -> bool:
    anomaly_names = (ISOLATION_FOREST_NAME, LOCAL_OUTLIER_FACTOR_NAME)
    return detector_name in anomaly_names or any(
        detector_name.startswith(f"{name}_") for name in anomaly_names
    )


def _is_supervised_detector_name(detector_name: str) -> bool:
    supervised_names = (LOGISTIC_REGRESSION_NAME, RANDOM_FOREST_NAME)
    return detector_name in supervised_names or any(
        detector_name.startswith(f"{name}_") for name in supervised_names
    )
