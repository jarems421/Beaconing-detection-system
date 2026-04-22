"""Evaluation path for CTU-13 bidirectional NetFlow data."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection import (
    HIGH_PRECISION_RULE_BASELINE_THRESHOLDS,
    LOCAL_OUTLIER_FACTOR_NAME,
    AnomalyDetectorConfig,
    SupervisedDetectorConfig,
    detect_flow_feature_rows,
    detect_flow_feature_rows_anomaly,
    detect_flow_feature_rows_supervised,
    fit_anomaly_detector,
    fit_supervised_detector,
)
from beacon_detector.detection.rules import FROZEN_RULE_BASELINE_NAME
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import build_flows
from beacon_detector.parsing import (
    Ctu13LabelPolicy,
    Ctu13ParseSummary,
    ctu13_feature_transfer_summary,
    load_ctu13_binetflow_events,
    map_ctu13_label,
)

from .cache import FEATURE_SCHEMA_VERSION, FeatureCacheConfig
from .metrics import ClassificationMetrics, calculate_classification_metrics
from .runner import SUPERVISED_TRAINING_SEEDS, build_supervised_training_features


@dataclass(frozen=True, slots=True)
class Ctu13EvaluationConfig:
    input_path: Path
    scenario_name: str
    output_dir: Path = Path("results/tables/ctu13")
    label_policy: Ctu13LabelPolicy = Ctu13LabelPolicy()
    max_rows: int | None = None
    max_background_benign_feature_rows: int | None = None
    benign_reference_fraction: float = 0.5
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS


@dataclass(frozen=True, slots=True)
class Ctu13ScenarioInput:
    input_path: Path
    scenario_name: str
    max_rows: int | None = None


@dataclass(frozen=True, slots=True)
class Ctu13PredictionRecord:
    detector_name: str
    operating_point: str
    ctu_scenario: str
    label_group: str
    scenario_name: str | None
    true_label: str
    predicted_label: str
    score: float
    event_count: int
    protocol: str
    dst_port: int
    total_bytes: int
    flow_duration_seconds: float | None
    mean_size_bytes: float | None
    size_cv: float | None
    triggered_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Ctu13DetectorEvaluation:
    detector_name: str
    operating_point: str
    metrics: ClassificationMetrics
    records: tuple[Ctu13PredictionRecord, ...]


@dataclass(frozen=True, slots=True)
class Ctu13FeatureDataset:
    feature_rows: tuple[FlowFeatures, ...]
    reference_benign_rows: tuple[FlowFeatures, ...]
    evaluation_rows: tuple[FlowFeatures, ...]
    parse_summary: Ctu13ParseSummary
    dropped_mixed_label_flow_count: int = 0
    capped_background_benign_flow_count: int = 0


@dataclass(frozen=True, slots=True)
class Ctu13EvaluationResult:
    config: Ctu13EvaluationConfig
    dataset: Ctu13FeatureDataset
    detector_results: tuple[Ctu13DetectorEvaluation, ...]


@dataclass(frozen=True, slots=True)
class Ctu13PolicyEvaluationResult:
    policy_name: str
    label_policy: Ctu13LabelPolicy
    scenario_results: tuple[Ctu13EvaluationResult, ...]
    detector_results: tuple[Ctu13DetectorEvaluation, ...]


@dataclass(frozen=True, slots=True)
class Ctu13MultiScenarioEvaluationResult:
    output_dir: Path
    scenario_inputs: tuple[Ctu13ScenarioInput, ...]
    conservative_result: Ctu13PolicyEvaluationResult
    background_sensitivity_result: Ctu13PolicyEvaluationResult | None = None


def build_ctu13_feature_dataset(config: Ctu13EvaluationConfig) -> Ctu13FeatureDataset:
    load_result = load_ctu13_binetflow_events(
        config.input_path,
        scenario_name=config.scenario_name,
        label_policy=config.label_policy,
        max_rows=config.max_rows,
    )
    flows = build_flows(load_result.events)
    clean_flows = [flow for flow in flows if not flow.has_mixed_labels]
    dropped_mixed_label_flow_count = len(flows) - len(clean_flows)
    feature_rows = tuple(extract_features_from_flows(clean_flows))
    feature_rows, capped_background_benign_flow_count = _cap_background_benign_rows(
        list(feature_rows),
        max_background_benign_feature_rows=config.max_background_benign_feature_rows,
    )
    reference_benign, evaluation_rows = _split_reference_and_evaluation_rows(
        list(feature_rows),
        benign_reference_fraction=config.benign_reference_fraction,
    )
    return Ctu13FeatureDataset(
        feature_rows=feature_rows,
        reference_benign_rows=tuple(reference_benign),
        evaluation_rows=tuple(evaluation_rows),
        parse_summary=load_result.summary,
        dropped_mixed_label_flow_count=dropped_mixed_label_flow_count,
        capped_background_benign_flow_count=capped_background_benign_flow_count,
    )


def run_ctu13_evaluation(
    config: Ctu13EvaluationConfig,
    *,
    cache_config: FeatureCacheConfig | None = None,
) -> Ctu13EvaluationResult:
    dataset = build_ctu13_feature_dataset(config)
    if not dataset.evaluation_rows:
        raise ValueError("No CTU-13 evaluation rows were produced.")

    detector_results = [
        _evaluate_rule_baseline(list(dataset.evaluation_rows)),
        _evaluate_lof_baseline(
            reference_rows=list(dataset.reference_benign_rows),
            evaluation_rows=list(dataset.evaluation_rows),
        ),
    ]
    detector_results.extend(
        _evaluate_rf_operating_points(
            evaluation_rows=list(dataset.evaluation_rows),
            training_seeds=config.training_seeds,
            cache_config=cache_config,
        )
    )
    return Ctu13EvaluationResult(
        config=config,
        dataset=dataset,
        detector_results=tuple(detector_results),
    )


def run_ctu13_multi_scenario_evaluation(
    *,
    scenarios: list[Ctu13ScenarioInput],
    output_dir: str | Path = "results/tables/ctu13_multi",
    include_background_sensitivity: bool = True,
    background_sensitivity_background_flow_cap: int | None = 10_000,
    benign_reference_fraction: float = 0.5,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> Ctu13MultiScenarioEvaluationResult:
    if not scenarios:
        raise ValueError("At least one CTU-13 scenario is required.")

    conservative_policy = Ctu13LabelPolicy()
    conservative_result = _run_ctu13_policy_evaluation(
        policy_name="conservative",
        label_policy=conservative_policy,
        scenarios=scenarios,
            output_dir=Path(output_dir),
            benign_reference_fraction=benign_reference_fraction,
            training_seeds=training_seeds,
            cache_config=cache_config,
            max_background_benign_feature_rows=None,
        )

    background_result = None
    if include_background_sensitivity:
        background_policy = Ctu13LabelPolicy(include_background_as_benign=True)
        background_result = _run_ctu13_policy_evaluation(
            policy_name="background_as_benign_sensitivity",
            label_policy=background_policy,
            scenarios=scenarios,
            output_dir=Path(output_dir),
            benign_reference_fraction=benign_reference_fraction,
            training_seeds=training_seeds,
            cache_config=cache_config,
            max_background_benign_feature_rows=(
                background_sensitivity_background_flow_cap
            ),
        )

    return Ctu13MultiScenarioEvaluationResult(
        output_dir=Path(output_dir),
        scenario_inputs=tuple(scenarios),
        conservative_result=conservative_result,
        background_sensitivity_result=background_result,
    )


def export_ctu13_evaluation_tables(result: Ctu13EvaluationResult) -> list[Path]:
    output_dir = result.config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write_detector_comparison(output_dir, result),
        _write_label_mapping_summary(output_dir, result),
        _write_feature_transfer_summary(output_dir),
        _write_per_scenario_metrics(output_dir, result),
        _write_metadata(output_dir, result),
    ]


def export_ctu13_multi_scenario_tables(
    result: Ctu13MultiScenarioEvaluationResult,
) -> list[Path]:
    output_dir = result.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write_multi_detector_comparison(output_dir, result),
        _write_multi_per_scenario_metrics(output_dir, result),
        _write_label_policy_sensitivity(output_dir, result),
        _write_false_positive_diagnostics(output_dir, result),
        _write_multi_metadata(output_dir, result),
    ]


def _run_ctu13_policy_evaluation(
    *,
    policy_name: str,
    label_policy: Ctu13LabelPolicy,
    scenarios: list[Ctu13ScenarioInput],
    output_dir: Path,
    benign_reference_fraction: float,
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
    max_background_benign_feature_rows: int | None,
) -> Ctu13PolicyEvaluationResult:
    scenario_results = []
    for scenario in scenarios:
        scenario_results.append(
            run_ctu13_evaluation(
                Ctu13EvaluationConfig(
                    input_path=scenario.input_path,
                    scenario_name=scenario.scenario_name,
                    output_dir=output_dir,
                    label_policy=label_policy,
                    max_rows=scenario.max_rows,
                    max_background_benign_feature_rows=max_background_benign_feature_rows,
                    benign_reference_fraction=benign_reference_fraction,
                    training_seeds=training_seeds,
                ),
                cache_config=cache_config,
            )
        )

    return Ctu13PolicyEvaluationResult(
        policy_name=policy_name,
        label_policy=label_policy,
        scenario_results=tuple(scenario_results),
        detector_results=tuple(_combine_detector_results(scenario_results)),
    )


def _combine_detector_results(
    scenario_results: list[Ctu13EvaluationResult],
) -> list[Ctu13DetectorEvaluation]:
    grouped_records: dict[str, list[Ctu13PredictionRecord]] = {}
    operating_points: dict[str, set[str]] = {}
    for scenario_result in scenario_results:
        for detector_result in scenario_result.detector_results:
            detector_name = detector_result.detector_name
            grouped_records.setdefault(detector_name, []).extend(detector_result.records)
            operating_points.setdefault(detector_name, set()).add(detector_result.operating_point)

    combined_results: list[Ctu13DetectorEvaluation] = []
    for detector_name, records in grouped_records.items():
        metrics = calculate_classification_metrics(
            [record.true_label for record in records],
            [record.predicted_label for record in records],
        )
        combined_results.append(
            Ctu13DetectorEvaluation(
                detector_name=detector_name,
                operating_point=_combined_operating_point(operating_points[detector_name]),
                metrics=metrics,
                records=tuple(records),
            )
        )
    return combined_results


def _combined_operating_point(operating_points: set[str]) -> str:
    if len(operating_points) == 1:
        return next(iter(operating_points))
    return "per_scenario_calibrated;" + ";".join(sorted(operating_points))


def _evaluate_rule_baseline(feature_rows: list[FlowFeatures]) -> Ctu13DetectorEvaluation:
    results = detect_flow_feature_rows(
        feature_rows,
        thresholds=HIGH_PRECISION_RULE_BASELINE_THRESHOLDS,
    )
    return _detector_evaluation_from_results(
        detector_name=FROZEN_RULE_BASELINE_NAME,
        operating_point=(
            f"threshold={HIGH_PRECISION_RULE_BASELINE_THRESHOLDS.prediction_threshold:g}"
        ),
        feature_rows=feature_rows,
        results=results,
    )


def _evaluate_lof_baseline(
    *,
    reference_rows: list[FlowFeatures],
    evaluation_rows: list[FlowFeatures],
) -> Ctu13DetectorEvaluation:
    if len(reference_rows) < 2:
        raise ValueError("CTU-13 LOF evaluation requires at least two benign reference flows.")

    config = AnomalyDetectorConfig()
    model = fit_anomaly_detector(
        reference_rows,
        detector_type="local_outlier_factor",
        config=config,
    )
    results = detect_flow_feature_rows_anomaly(evaluation_rows, model=model)
    return _detector_evaluation_from_results(
        detector_name=LOCAL_OUTLIER_FACTOR_NAME,
        operating_point=(
            f"ctu13_benign_reference;contamination={config.contamination:g};"
            f"threshold={model.prediction_threshold:g};"
            f"calibration_flows={model.calibration_flow_count}"
        ),
        feature_rows=evaluation_rows,
        results=results,
    )


def _evaluate_rf_operating_points(
    *,
    evaluation_rows: list[FlowFeatures],
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[Ctu13DetectorEvaluation]:
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        cache_config=cache_config,
    )
    detector_results: list[Ctu13DetectorEvaluation] = []
    for detector_name, threshold in (
        ("rf_full_threshold_0p6", 0.6),
        ("rf_full_threshold_0p3", 0.3),
    ):
        config = SupervisedDetectorConfig(prediction_threshold=threshold)
        model = fit_supervised_detector(
            training_features,
            detector_type="random_forest",
            config=config,
        )
        results = detect_flow_feature_rows_supervised(evaluation_rows, model=model)
        detector_results.append(
            _detector_evaluation_from_results(
                detector_name=detector_name,
                operating_point=f"synthetic_training;threshold={threshold:g};features=full",
                feature_rows=evaluation_rows,
                results=results,
            )
        )
    return detector_results


def _detector_evaluation_from_results(
    *,
    detector_name: str,
    operating_point: str,
    feature_rows: list[FlowFeatures],
    results,
) -> Ctu13DetectorEvaluation:
    feature_by_key = {row.flow_key: row for row in feature_rows}
    records: list[Ctu13PredictionRecord] = []
    for result in results:
        features = feature_by_key[result.flow_key]
        records.append(
            Ctu13PredictionRecord(
                detector_name=detector_name,
                operating_point=operating_point,
                ctu_scenario=_ctu_scenario(result.scenario_name),
                label_group=_ctu_label_group(result.scenario_name),
                scenario_name=result.scenario_name,
                true_label=result.true_label,
                predicted_label=result.predicted_label,
                score=result.score,
                event_count=features.event_count,
                protocol=features.flow_key.protocol,
                dst_port=features.flow_key.dst_port,
                total_bytes=features.total_bytes,
                flow_duration_seconds=features.flow_duration_seconds,
                mean_size_bytes=features.mean_size_bytes,
                size_cv=features.size_cv,
                triggered_rules=tuple(
                    contribution.rule_name
                    for contribution in result.contributions
                    if contribution.fired and contribution.score > 0
                ),
            )
        )

    metrics = calculate_classification_metrics(
        [record.true_label for record in records],
        [record.predicted_label for record in records],
    )
    return Ctu13DetectorEvaluation(
        detector_name=detector_name,
        operating_point=operating_point,
        metrics=metrics,
        records=tuple(records),
    )


def _split_reference_and_evaluation_rows(
    feature_rows: list[FlowFeatures],
    *,
    benign_reference_fraction: float,
) -> tuple[list[FlowFeatures], list[FlowFeatures]]:
    if not 0 < benign_reference_fraction < 1:
        raise ValueError("benign_reference_fraction must be between 0 and 1.")

    benign_rows = sorted(
        [row for row in feature_rows if row.label == "benign"],
        key=_stable_feature_row_key,
    )
    beacon_rows = sorted(
        [row for row in feature_rows if row.label == "beacon"],
        key=_stable_feature_row_key,
    )
    reference_count = max(2, int(len(benign_rows) * benign_reference_fraction))
    reference_count = min(reference_count, len(benign_rows))

    reference_benign_rows = benign_rows[:reference_count]
    heldout_benign_rows = benign_rows[reference_count:]
    evaluation_rows = heldout_benign_rows + beacon_rows
    return reference_benign_rows, evaluation_rows


def _cap_background_benign_rows(
    feature_rows: list[FlowFeatures],
    *,
    max_background_benign_feature_rows: int | None,
) -> tuple[tuple[FlowFeatures, ...], int]:
    if max_background_benign_feature_rows is None:
        return tuple(feature_rows), 0
    if max_background_benign_feature_rows < 0:
        raise ValueError("max_background_benign_feature_rows must be non-negative.")

    background_rows = sorted(
        [
            row
            for row in feature_rows
            if row.label == "benign"
            and (row.scenario_name or "").endswith(":ctu13_background")
        ],
        key=_stable_feature_row_key,
    )
    if len(background_rows) <= max_background_benign_feature_rows:
        return tuple(feature_rows), 0

    retained_background_keys = {
        row.flow_key for row in background_rows[:max_background_benign_feature_rows]
    }
    retained_rows = [
        row
        for row in feature_rows
        if not (
            row.label == "benign"
            and (row.scenario_name or "").endswith(":ctu13_background")
            and row.flow_key not in retained_background_keys
        )
    ]
    return (
        tuple(sorted(retained_rows, key=_stable_feature_row_key)),
        len(background_rows) - max_background_benign_feature_rows,
    )


def _stable_feature_row_key(row: FlowFeatures) -> str:
    flow_key = row.flow_key
    identity = "|".join(
        (
            flow_key.src_ip,
            flow_key.src_port or "",
            flow_key.direction or "",
            flow_key.dst_ip,
            str(flow_key.dst_port),
            flow_key.protocol,
            row.scenario_name or "",
            row.label,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _write_detector_comparison(
    output_dir: Path,
    result: Ctu13EvaluationResult,
) -> Path:
    path = output_dir / "ctu13_detector_comparison.csv"
    rows: list[dict[str, Any]] = []
    for detector_result in result.detector_results:
        metrics = detector_result.metrics
        matrix = metrics.confusion_matrix
        rows.append(
            {
                "detector_name": detector_result.detector_name,
                "operating_point": detector_result.operating_point,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1_score,
                "false_positive_rate": metrics.false_positive_rate,
                "tp": matrix.true_positive,
                "fp": matrix.false_positive,
                "tn": matrix.true_negative,
                "fn": matrix.false_negative,
                "evaluated_flow_count": len(detector_result.records),
            }
        )
    _write_csv(path, rows)
    return path


def _write_label_mapping_summary(
    output_dir: Path,
    result: Ctu13EvaluationResult,
) -> Path:
    path = output_dir / "ctu13_label_mapping_summary.csv"
    rows: list[dict[str, Any]] = []
    policy = result.config.label_policy
    for raw_label, count in sorted(result.dataset.parse_summary.raw_label_counts.items()):
        rows.append(
            {
                "raw_label": raw_label,
                "row_count": count,
                "mapped_label": map_ctu13_label(raw_label, policy),
            }
        )
    _write_csv(path, rows)
    return path


def _write_feature_transfer_summary(output_dir: Path) -> Path:
    path = output_dir / "ctu13_feature_transfer_summary.csv"
    _write_csv(path, ctu13_feature_transfer_summary())
    return path


def _write_per_scenario_metrics(
    output_dir: Path,
    result: Ctu13EvaluationResult,
) -> Path:
    path = output_dir / "ctu13_per_scenario_metrics.csv"
    rows: list[dict[str, Any]] = []
    for detector_result in result.detector_results:
        scenario_names = sorted(
            {record.scenario_name or "unknown" for record in detector_result.records}
        )
        for scenario_name in scenario_names:
            scenario_records = [
                record
                for record in detector_result.records
                if (record.scenario_name or "unknown") == scenario_name
            ]
            metrics = calculate_classification_metrics(
                [record.true_label for record in scenario_records],
                [record.predicted_label for record in scenario_records],
            )
            matrix = metrics.confusion_matrix
            rows.append(
                {
                    "detector_name": detector_result.detector_name,
                    "operating_point": detector_result.operating_point,
                    "scenario_name": scenario_name,
                    "precision": metrics.precision,
                    "recall": metrics.recall,
                    "f1": metrics.f1_score,
                    "false_positive_rate": metrics.false_positive_rate,
                    "tp": matrix.true_positive,
                    "fp": matrix.false_positive,
                    "tn": matrix.true_negative,
                    "fn": matrix.false_negative,
                    "flow_count": len(scenario_records),
                }
            )
    _write_csv(path, rows)
    return path


def _write_metadata(output_dir: Path, result: Ctu13EvaluationResult) -> Path:
    path = output_dir / "ctu13_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "CTU-13 bidirectional NetFlow",
        "input_path": str(result.config.input_path),
        "scenario_name": result.config.scenario_name,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "label_policy": asdict(result.config.label_policy),
        "max_rows": result.config.max_rows,
        "max_background_benign_feature_rows": (
            result.config.max_background_benign_feature_rows
        ),
        "benign_reference_fraction": result.config.benign_reference_fraction,
        "training_seed_list": list(result.config.training_seeds),
        "parse_summary": asdict(result.dataset.parse_summary),
        "feature_row_count": len(result.dataset.feature_rows),
        "dropped_mixed_label_flow_count": result.dataset.dropped_mixed_label_flow_count,
        "capped_background_benign_flow_count": (
            result.dataset.capped_background_benign_flow_count
        ),
        "reference_benign_flow_count": len(result.dataset.reference_benign_rows),
        "evaluation_flow_count": len(result.dataset.evaluation_rows),
        "detectors": [
            {
                "detector_name": detector_result.detector_name,
                "operating_point": detector_result.operating_point,
            }
            for detector_result in result.detector_results
        ],
        "limitations": [
            "CTU-13 rows are bidirectional flow records, not raw packets.",
            (
                "Current feature extraction treats each CTU-13 row as a connection-level event "
                "and computes behaviour across repeated flow records sharing the richer CTU "
                "FlowKey including source port and direction."
            ),
            "Mixed-label grouped flows are dropped before feature extraction and counted.",
            "Background and To-* labels are excluded by default because they are ambiguous.",
            (
                "Random Forest operating points are trained on synthetic features and evaluated "
                "directly on adapted CTU-13 features."
            ),
            (
                "LOF uses a held-out CTU-13 benign reference split because anomaly baselines "
                "require benign reference behaviour; its threshold is calibrated from a "
                "separate benign subset inside that reference split."
            ),
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _write_multi_detector_comparison(
    output_dir: Path,
    result: Ctu13MultiScenarioEvaluationResult,
) -> Path:
    path = output_dir / "ctu13_multi_scenario_detector_comparison.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            metrics = detector_result.metrics
            matrix = metrics.confusion_matrix
            rows.append(
                {
                    "policy_name": policy_result.policy_name,
                    "detector_name": detector_result.detector_name,
                    "operating_point": detector_result.operating_point,
                    "precision": metrics.precision,
                    "recall": metrics.recall,
                    "f1": metrics.f1_score,
                    "false_positive_rate": metrics.false_positive_rate,
                    "tp": matrix.true_positive,
                    "fp": matrix.false_positive,
                    "tn": matrix.true_negative,
                    "fn": matrix.false_negative,
                    "evaluated_flow_count": len(detector_result.records),
                }
            )
    _write_csv(path, rows)
    return path


def _write_multi_per_scenario_metrics(
    output_dir: Path,
    result: Ctu13MultiScenarioEvaluationResult,
) -> Path:
    path = output_dir / "ctu13_multi_scenario_per_scenario_metrics.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            rows.extend(
                _scenario_metric_rows(
                    policy_name=policy_result.policy_name,
                    detector_result=detector_result,
                )
            )
    _write_csv(path, rows)
    return path


def _write_label_policy_sensitivity(
    output_dir: Path,
    result: Ctu13MultiScenarioEvaluationResult,
) -> Path:
    path = output_dir / "ctu13_label_policy_sensitivity.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        parsed_events = sum(
            scenario_result.dataset.parse_summary.parsed_events
            for scenario_result in policy_result.scenario_results
        )
        skipped_rows = sum(
            scenario_result.dataset.parse_summary.skipped_rows
            for scenario_result in policy_result.scenario_results
        )
        feature_rows = sum(
            len(scenario_result.dataset.feature_rows)
            for scenario_result in policy_result.scenario_results
        )
        capped_background_benign_flows = sum(
            scenario_result.dataset.capped_background_benign_flow_count
            for scenario_result in policy_result.scenario_results
        )
        for detector_result in policy_result.detector_results:
            metrics = detector_result.metrics
            matrix = metrics.confusion_matrix
            rows.append(
                {
                    "policy_name": policy_result.policy_name,
                    "include_background_as_benign": (
                        policy_result.label_policy.include_background_as_benign
                    ),
                    "include_to_normal_as_benign": (
                        policy_result.label_policy.include_to_normal_as_benign
                    ),
                    "include_to_botnet_as_beacon": (
                        policy_result.label_policy.include_to_botnet_as_beacon
                    ),
                    "detector_name": detector_result.detector_name,
                    "operating_point": detector_result.operating_point,
                    "precision": metrics.precision,
                    "recall": metrics.recall,
                    "f1": metrics.f1_score,
                    "false_positive_rate": metrics.false_positive_rate,
                    "tp": matrix.true_positive,
                    "fp": matrix.false_positive,
                    "tn": matrix.true_negative,
                    "fn": matrix.false_negative,
                    "parsed_events": parsed_events,
                    "skipped_rows": skipped_rows,
                    "feature_rows": feature_rows,
                    "capped_background_benign_flows": capped_background_benign_flows,
                }
            )
    _write_csv(path, rows)
    return path


def _write_false_positive_diagnostics(
    output_dir: Path,
    result: Ctu13MultiScenarioEvaluationResult,
) -> Path:
    path = output_dir / "ctu13_false_positive_diagnostics.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            false_positives = [
                record
                for record in detector_result.records
                if record.true_label != "beacon" and record.predicted_label == "beacon"
            ]
            grouped: dict[tuple[str, str, str, int], list[Ctu13PredictionRecord]] = {}
            for record in false_positives:
                key = (
                    record.ctu_scenario,
                    record.label_group,
                    record.protocol,
                    record.dst_port,
                )
                grouped.setdefault(key, []).append(record)

            for (ctu_scenario, label_group, protocol, dst_port), records in sorted(
                grouped.items(),
                key=lambda item: len(item[1]),
                reverse=True,
            ):
                rows.append(
                    {
                        "policy_name": policy_result.policy_name,
                        "detector_name": detector_result.detector_name,
                        "operating_point": detector_result.operating_point,
                        "ctu_scenario": ctu_scenario,
                        "label_group": label_group,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "false_positive_count": len(records),
                        "mean_score": _mean([record.score for record in records]),
                        "mean_event_count": _mean([record.event_count for record in records]),
                        "mean_total_bytes": _mean([record.total_bytes for record in records]),
                        "mean_flow_duration_seconds": _mean(
                            [
                                record.flow_duration_seconds
                                for record in records
                                if record.flow_duration_seconds is not None
                            ]
                        ),
                        "mean_size_cv": _mean(
                            [
                                record.size_cv
                                for record in records
                                if record.size_cv is not None
                            ]
                        ),
                    }
                )
    _write_csv(path, rows)
    return path


def _write_multi_metadata(
    output_dir: Path,
    result: Ctu13MultiScenarioEvaluationResult,
) -> Path:
    path = output_dir / "ctu13_multi_scenario_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "CTU-13 bidirectional NetFlow",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "scenario_inputs": [
            {
                "scenario_name": scenario.scenario_name,
                "input_path": str(scenario.input_path),
                "max_rows": scenario.max_rows,
            }
            for scenario in result.scenario_inputs
        ],
        "policy_results": [
            {
                "policy_name": policy_result.policy_name,
                "label_policy": asdict(policy_result.label_policy),
                "scenario_parse_summaries": [
                    asdict(scenario_result.dataset.parse_summary)
                    for scenario_result in policy_result.scenario_results
                ],
                "dropped_mixed_label_flow_count": sum(
                    scenario_result.dataset.dropped_mixed_label_flow_count
                    for scenario_result in policy_result.scenario_results
                ),
                "capped_background_benign_flow_count": sum(
                    scenario_result.dataset.capped_background_benign_flow_count
                    for scenario_result in policy_result.scenario_results
                ),
                "detectors": [
                    {
                        "detector_name": detector_result.detector_name,
                        "operating_point": detector_result.operating_point,
                    }
                    for detector_result in policy_result.detector_results
                ],
            }
            for policy_result in _policy_results(result)
        ],
        "interpretation_notes": [
            "Conservative policy is the primary CTU-13 direct-transfer result.",
            (
                "Background-as-benign is a sensitivity analysis, not the headline result, "
                "because CTU-13 Background traffic is ambiguous."
            ),
            (
                "Background-as-benign direct-transfer runs cap retained CTU background "
                "feature rows per scenario by default so the optional LOF sensitivity "
                "analysis remains reproducible on a local workstation."
            ),
            (
                "LOF uses a per-scenario held-out benign reference split; RF uses the existing "
                "synthetic training seeds."
            ),
            "No detector thresholds or logic are changed by this public-data evaluation.",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _scenario_metric_rows(
    *,
    policy_name: str,
    detector_result: Ctu13DetectorEvaluation,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ctu_scenario in sorted({record.ctu_scenario for record in detector_result.records}):
        scenario_records = [
            record for record in detector_result.records if record.ctu_scenario == ctu_scenario
        ]
        rows.append(
            _metrics_row(
                policy_name=policy_name,
                detector_result=detector_result,
                ctu_scenario=ctu_scenario,
                label_group="all",
                records=scenario_records,
            )
        )
        for label_group in sorted({record.label_group for record in scenario_records}):
            label_records = [
                record for record in scenario_records if record.label_group == label_group
            ]
            rows.append(
                _metrics_row(
                    policy_name=policy_name,
                    detector_result=detector_result,
                    ctu_scenario=ctu_scenario,
                    label_group=label_group,
                    records=label_records,
                )
            )
    return rows


def _metrics_row(
    *,
    policy_name: str,
    detector_result: Ctu13DetectorEvaluation,
    ctu_scenario: str,
    label_group: str,
    records: list[Ctu13PredictionRecord],
) -> dict[str, Any]:
    metrics = calculate_classification_metrics(
        [record.true_label for record in records],
        [record.predicted_label for record in records],
    )
    matrix = metrics.confusion_matrix
    return {
        "policy_name": policy_name,
        "detector_name": detector_result.detector_name,
        "operating_point": detector_result.operating_point,
        "ctu_scenario": ctu_scenario,
        "label_group": label_group,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1_score,
        "false_positive_rate": metrics.false_positive_rate,
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "flow_count": len(records),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = _fieldnames(rows)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames


def _policy_results(
    result: Ctu13MultiScenarioEvaluationResult,
) -> tuple[Ctu13PolicyEvaluationResult, ...]:
    if result.background_sensitivity_result is None:
        return (result.conservative_result,)
    return (result.conservative_result, result.background_sensitivity_result)


def _ctu_scenario(scenario_name: str | None) -> str:
    if not scenario_name:
        return "unknown"
    return scenario_name.split(":", maxsplit=1)[0]


def _ctu_label_group(scenario_name: str | None) -> str:
    if not scenario_name or ":" not in scenario_name:
        return "unknown"
    return scenario_name.split(":", maxsplit=1)[1]


def _mean(values: list[float | int]) -> float | None:
    if not values:
        return None
    return float(sum(values) / len(values))
