"""Within-CTU supervised evaluation using CTU-native feature rows."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from beacon_detector.features.ctu_native import (
    CTU13_NATIVE_NUMERIC_FEATURES,
    Ctu13NativeFeatures,
    native_features_from_ctu13_records,
)
from beacon_detector.parsing import Ctu13LabelPolicy, load_ctu13_binetflow_events

from .ctu13 import Ctu13ScenarioInput
from .metrics import ClassificationMetrics, calculate_classification_metrics

SYNTHETIC_TRANSFER_STAGE = "Synthetic direct transfer to CTU"
CTU_NATIVE_UNSUPERVISED_STAGE = "CTU-native unsupervised evaluation"
WITHIN_CTU_SUPERVISED_STAGE = "Within-CTU supervised evaluation"

CtuNativeSupervisedDetectorType = Literal["logistic_regression", "random_forest"]

CTU_NATIVE_LOGISTIC_REGRESSION_NAME = "ctu_native_logistic_regression_v1"
CTU_NATIVE_RANDOM_FOREST_NAME = "ctu_native_random_forest_v1"


@dataclass(frozen=True, slots=True)
class CtuSupervisedConfig:
    feature_names: tuple[str, ...] = CTU13_NATIVE_NUMERIC_FEATURES
    missing_value: float = 0.0
    prediction_threshold: float = 0.5
    random_state: int = 42
    logistic_max_iter: int = 1000
    random_forest_estimators: int = 200
    random_forest_max_depth: int | None = 8
    random_forest_min_samples_leaf: int = 2


@dataclass(frozen=True, slots=True)
class CtuScenarioSplit:
    fold_name: str
    train_scenario_names: tuple[str, ...]
    test_scenario_name: str


@dataclass(frozen=True, slots=True)
class CtuSupervisedModel:
    detector_name: str
    detector_type: CtuNativeSupervisedDetectorType
    config: CtuSupervisedConfig
    scaler: StandardScaler
    estimator: Any
    train_flow_count: int
    train_beacon_count: int
    train_benign_count: int


@dataclass(frozen=True, slots=True)
class CtuSupervisedPredictionRecord:
    policy_name: str
    detector_name: str
    operating_point: str
    story_stage: str
    fold_name: str
    train_scenarios: tuple[str, ...]
    test_scenario: str
    label_group: str
    true_label: str
    predicted_label: str
    score: float
    protocol: str
    dst_port: int
    service_bucket: str
    duration_seconds: float
    total_packets: int
    total_bytes: int
    src_bytes: int
    dst_bytes: int
    src_byte_ratio: float | None
    dst_byte_ratio: float | None
    packets_per_second: float | None
    bytes_per_second: float | None


@dataclass(frozen=True, slots=True)
class CtuSupervisedDetectorEvaluation:
    policy_name: str
    detector_name: str
    operating_point: str
    story_stage: str
    metrics: ClassificationMetrics
    records: tuple[CtuSupervisedPredictionRecord, ...]
    feature_importances: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class CtuSupervisedPolicyResult:
    policy_name: str
    label_policy: Ctu13LabelPolicy
    rows_by_scenario: dict[str, tuple[Ctu13NativeFeatures, ...]]
    splits: tuple[CtuScenarioSplit, ...]
    detector_results: tuple[CtuSupervisedDetectorEvaluation, ...]


@dataclass(frozen=True, slots=True)
class CtuSupervisedEvaluationResult:
    output_dir: Path
    scenarios: tuple[Ctu13ScenarioInput, ...]
    config: CtuSupervisedConfig
    conservative_result: CtuSupervisedPolicyResult
    background_sensitivity_result: CtuSupervisedPolicyResult | None = None


def build_leave_one_scenario_splits(
    scenarios: list[Ctu13ScenarioInput] | tuple[Ctu13ScenarioInput, ...],
) -> tuple[CtuScenarioSplit, ...]:
    if len(scenarios) < 2:
        raise ValueError("At least two CTU scenarios are required for scenario-aware splits.")

    scenario_names = tuple(scenario.scenario_name for scenario in scenarios)
    if len(set(scenario_names)) != len(scenario_names):
        raise ValueError("CTU scenario names must be unique.")

    return tuple(
        CtuScenarioSplit(
            fold_name=f"test_{test_name}",
            train_scenario_names=tuple(name for name in scenario_names if name != test_name),
            test_scenario_name=test_name,
        )
        for test_name in scenario_names
    )


def run_ctu_supervised_evaluation(
    *,
    scenarios: list[Ctu13ScenarioInput],
    output_dir: str | Path = "results/tables/ctu13_supervised",
    include_background_sensitivity: bool = True,
    config: CtuSupervisedConfig | None = None,
) -> CtuSupervisedEvaluationResult:
    if not scenarios:
        raise ValueError("At least one CTU-13 scenario is required.")

    config = config or CtuSupervisedConfig()
    conservative_result = _run_policy_supervised_evaluation(
        policy_name="conservative",
        label_policy=Ctu13LabelPolicy(),
        scenarios=scenarios,
        config=config,
    )

    background_result = None
    if include_background_sensitivity:
        background_result = _run_policy_supervised_evaluation(
            policy_name="background_as_benign_sensitivity",
            label_policy=Ctu13LabelPolicy(include_background_as_benign=True),
            scenarios=scenarios,
            config=config,
        )

    return CtuSupervisedEvaluationResult(
        output_dir=Path(output_dir),
        scenarios=tuple(scenarios),
        config=config,
        conservative_result=conservative_result,
        background_sensitivity_result=background_result,
    )


def export_ctu_supervised_tables(result: CtuSupervisedEvaluationResult) -> list[Path]:
    result.output_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write_detector_comparison(result),
        _write_per_scenario_metrics(result),
        _write_feature_importance(result),
        _write_label_policy_sensitivity(result),
        _write_false_diagnostic(
            result,
            predicted_label="beacon",
            file_name="ctu_supervised_false_positive_diagnostics.csv",
        ),
        _write_false_diagnostic(
            result,
            predicted_label="benign",
            file_name="ctu_supervised_false_negative_diagnostics.csv",
        ),
        _write_metadata(result),
    ]


def fit_ctu_native_supervised_detector(
    rows: list[Ctu13NativeFeatures],
    *,
    detector_type: CtuNativeSupervisedDetectorType,
    config: CtuSupervisedConfig | None = None,
) -> CtuSupervisedModel:
    config = config or CtuSupervisedConfig()
    if len(rows) < 2:
        raise ValueError("At least two CTU-native training rows are required.")

    labels = [_label_to_int(row.label) for row in rows]
    if len(set(labels)) < 2:
        raise ValueError("CTU-native supervised training requires benign and beacon rows.")

    scaler = StandardScaler()
    matrix = _feature_matrix(rows, config)
    scaled_matrix = scaler.fit_transform(matrix)
    estimator = _fit_estimator(detector_type, scaled_matrix, labels, config)
    beacon_count = sum(labels)

    return CtuSupervisedModel(
        detector_name=_detector_name(detector_type),
        detector_type=detector_type,
        config=config,
        scaler=scaler,
        estimator=estimator,
        train_flow_count=len(rows),
        train_beacon_count=beacon_count,
        train_benign_count=len(rows) - beacon_count,
    )


def predict_ctu_native_supervised(
    rows: list[Ctu13NativeFeatures],
    *,
    model: CtuSupervisedModel,
) -> list[tuple[Ctu13NativeFeatures, float, str]]:
    if not rows:
        return []
    matrix = _feature_matrix(rows, model.config)
    scaled_matrix = model.scaler.transform(matrix)
    probabilities = model.estimator.predict_proba(scaled_matrix)[:, 1]
    return [
        (
            row,
            float(probability),
            "beacon" if float(probability) >= model.config.prediction_threshold else "benign",
        )
        for row, probability in zip(rows, probabilities, strict=False)
    ]


def ctu_supervised_operating_point(config: CtuSupervisedConfig) -> str:
    return (
        f"ctu_native_training;threshold={config.prediction_threshold:g};"
        f"features={len(config.feature_names)}"
    )


def _run_policy_supervised_evaluation(
    *,
    policy_name: str,
    label_policy: Ctu13LabelPolicy,
    scenarios: list[Ctu13ScenarioInput],
    config: CtuSupervisedConfig,
) -> CtuSupervisedPolicyResult:
    rows_by_scenario = _load_rows_by_scenario(scenarios, label_policy=label_policy)
    splits = build_leave_one_scenario_splits(scenarios)
    detector_results = []
    for detector_type in ("logistic_regression", "random_forest"):
        detector_results.append(
            _evaluate_detector_type(
                policy_name=policy_name,
                rows_by_scenario=rows_by_scenario,
                splits=splits,
                detector_type=detector_type,
                config=config,
            )
        )

    return CtuSupervisedPolicyResult(
        policy_name=policy_name,
        label_policy=label_policy,
        rows_by_scenario=rows_by_scenario,
        splits=splits,
        detector_results=tuple(detector_results),
    )


def _load_rows_by_scenario(
    scenarios: list[Ctu13ScenarioInput],
    *,
    label_policy: Ctu13LabelPolicy,
) -> dict[str, tuple[Ctu13NativeFeatures, ...]]:
    rows_by_scenario: dict[str, tuple[Ctu13NativeFeatures, ...]] = {}
    for scenario in scenarios:
        load_result = load_ctu13_binetflow_events(
            scenario.input_path,
            scenario_name=scenario.scenario_name,
            label_policy=label_policy,
            max_rows=scenario.max_rows,
        )
        rows_by_scenario[scenario.scenario_name] = tuple(
            native_features_from_ctu13_records(
                load_result.records,
                scenario_name=scenario.scenario_name,
            )
        )
    return rows_by_scenario


def _evaluate_detector_type(
    *,
    policy_name: str,
    rows_by_scenario: dict[str, tuple[Ctu13NativeFeatures, ...]],
    splits: tuple[CtuScenarioSplit, ...],
    detector_type: CtuNativeSupervisedDetectorType,
    config: CtuSupervisedConfig,
) -> CtuSupervisedDetectorEvaluation:
    records: list[CtuSupervisedPredictionRecord] = []
    importance_rows: list[dict[str, Any]] = []

    for split in splits:
        train_rows = [
            row
            for scenario_name in split.train_scenario_names
            for row in rows_by_scenario.get(scenario_name, ())
        ]
        test_rows = list(rows_by_scenario.get(split.test_scenario_name, ()))
        if not train_rows or not test_rows:
            continue

        model = fit_ctu_native_supervised_detector(
            train_rows,
            detector_type=detector_type,
            config=config,
        )
        importance_rows.extend(_model_importance_rows(model, split=split, policy_name=policy_name))
        predictions = predict_ctu_native_supervised(test_rows, model=model)
        for row, score, predicted_label in predictions:
            records.append(
                CtuSupervisedPredictionRecord(
                    policy_name=policy_name,
                    detector_name=model.detector_name,
                    operating_point=ctu_supervised_operating_point(config),
                    story_stage=WITHIN_CTU_SUPERVISED_STAGE,
                    fold_name=split.fold_name,
                    train_scenarios=split.train_scenario_names,
                    test_scenario=split.test_scenario_name,
                    label_group=row.label_group,
                    true_label=row.label,
                    predicted_label=predicted_label,
                    score=score,
                    protocol=row.protocol,
                    dst_port=row.dst_port,
                    service_bucket=row.service_bucket,
                    duration_seconds=row.duration_seconds,
                    total_packets=row.total_packets,
                    total_bytes=row.total_bytes,
                    src_bytes=row.src_bytes,
                    dst_bytes=row.dst_bytes,
                    src_byte_ratio=row.src_byte_ratio,
                    dst_byte_ratio=row.dst_byte_ratio,
                    packets_per_second=row.packets_per_second,
                    bytes_per_second=row.bytes_per_second,
                )
            )

    if not records:
        raise ValueError("No CTU-native supervised predictions were produced.")

    metrics = calculate_classification_metrics(
        [record.true_label for record in records],
        [record.predicted_label for record in records],
    )
    return CtuSupervisedDetectorEvaluation(
        policy_name=policy_name,
        detector_name=_detector_name(detector_type),
        operating_point=ctu_supervised_operating_point(config),
        story_stage=WITHIN_CTU_SUPERVISED_STAGE,
        metrics=metrics,
        records=tuple(records),
        feature_importances=tuple(importance_rows),
    )


def _fit_estimator(
    detector_type: CtuNativeSupervisedDetectorType,
    scaled_matrix: Any,
    labels: list[int],
    config: CtuSupervisedConfig,
) -> Any:
    if detector_type == "logistic_regression":
        return LogisticRegression(
            max_iter=config.logistic_max_iter,
            class_weight="balanced",
            random_state=config.random_state,
        ).fit(scaled_matrix, labels)
    if detector_type == "random_forest":
        return RandomForestClassifier(
            n_estimators=config.random_forest_estimators,
            max_depth=config.random_forest_max_depth,
            min_samples_leaf=config.random_forest_min_samples_leaf,
            class_weight="balanced",
            random_state=config.random_state,
        ).fit(scaled_matrix, labels)
    raise ValueError(f"Unsupported CTU-native supervised detector: {detector_type}")


def _feature_matrix(
    rows: list[Ctu13NativeFeatures], config: CtuSupervisedConfig
) -> list[list[float]]:
    return [
        [
            _feature_value(row, feature_name, config.missing_value)
            for feature_name in config.feature_names
        ]
        for row in rows
    ]


def _feature_value(row: Ctu13NativeFeatures, feature_name: str, missing_value: float) -> float:
    value = getattr(row, feature_name)
    if value is None:
        return missing_value
    return float(value)


def _label_to_int(label: str) -> int:
    if label == "beacon":
        return 1
    if label == "benign":
        return 0
    raise ValueError(f"Unsupported CTU label: {label}")


def _detector_name(detector_type: CtuNativeSupervisedDetectorType) -> str:
    if detector_type == "logistic_regression":
        return CTU_NATIVE_LOGISTIC_REGRESSION_NAME
    if detector_type == "random_forest":
        return CTU_NATIVE_RANDOM_FOREST_NAME
    raise ValueError(f"Unsupported CTU-native supervised detector: {detector_type}")


def _model_importance_rows(
    model: CtuSupervisedModel,
    *,
    split: CtuScenarioSplit,
    policy_name: str,
) -> list[dict[str, Any]]:
    if model.detector_type == "logistic_regression":
        values = model.estimator.coef_[0]
        value_name = "coefficient"
    else:
        values = model.estimator.feature_importances_
        value_name = "feature_importance"

    rows = []
    for feature_name, value in zip(model.config.feature_names, values, strict=False):
        rows.append(
            {
                "policy_name": policy_name,
                "story_stage": WITHIN_CTU_SUPERVISED_STAGE,
                "detector_name": model.detector_name,
                "operating_point": ctu_supervised_operating_point(model.config),
                "fold_name": split.fold_name,
                "train_scenarios": ";".join(split.train_scenario_names),
                "test_scenario": split.test_scenario_name,
                "feature_name": feature_name,
                "value_type": value_name,
                "value": float(value),
                "absolute_value": abs(float(value)),
            }
        )
    return rows


def _write_detector_comparison(result: CtuSupervisedEvaluationResult) -> Path:
    path = result.output_dir / "ctu_supervised_detector_comparison.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            matrix = detector_result.metrics.confusion_matrix
            rows.append(
                {
                    "story_stage": detector_result.story_stage,
                    "policy_name": policy_result.policy_name,
                    "detector_name": detector_result.detector_name,
                    "operating_point": detector_result.operating_point,
                    "precision": detector_result.metrics.precision,
                    "recall": detector_result.metrics.recall,
                    "f1": detector_result.metrics.f1_score,
                    "false_positive_rate": detector_result.metrics.false_positive_rate,
                    "tp": matrix.true_positive,
                    "fp": matrix.false_positive,
                    "tn": matrix.true_negative,
                    "fn": matrix.false_negative,
                    "evaluated_flow_count": len(detector_result.records),
                }
            )
    _write_csv(path, rows)
    return path


def _write_per_scenario_metrics(result: CtuSupervisedEvaluationResult) -> Path:
    path = result.output_dir / "ctu_supervised_per_scenario_metrics.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            for scenario_name in sorted(
                {record.test_scenario for record in detector_result.records}
            ):
                scenario_records = [
                    record
                    for record in detector_result.records
                    if record.test_scenario == scenario_name
                ]
                rows.append(
                    _metric_row(
                        policy_name=policy_result.policy_name,
                        detector_result=detector_result,
                        scenario_name=scenario_name,
                        label_group="all",
                        records=scenario_records,
                    )
                )
                for label_group in sorted({record.label_group for record in scenario_records}):
                    label_records = [
                        record for record in scenario_records if record.label_group == label_group
                    ]
                    rows.append(
                        _metric_row(
                            policy_name=policy_result.policy_name,
                            detector_result=detector_result,
                            scenario_name=scenario_name,
                            label_group=label_group,
                            records=label_records,
                        )
                    )
    _write_csv(path, rows)
    return path


def _metric_row(
    *,
    policy_name: str,
    detector_result: CtuSupervisedDetectorEvaluation,
    scenario_name: str,
    label_group: str,
    records: list[CtuSupervisedPredictionRecord],
) -> dict[str, Any]:
    metrics = calculate_classification_metrics(
        [record.true_label for record in records],
        [record.predicted_label for record in records],
    )
    matrix = metrics.confusion_matrix
    return {
        "story_stage": detector_result.story_stage,
        "policy_name": policy_name,
        "detector_name": detector_result.detector_name,
        "operating_point": detector_result.operating_point,
        "ctu_scenario": scenario_name,
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


def _write_feature_importance(result: CtuSupervisedEvaluationResult) -> Path:
    path = result.output_dir / "ctu_supervised_feature_importance.csv"
    rows = [
        row
        for policy_result in _policy_results(result)
        for detector_result in policy_result.detector_results
        for row in detector_result.feature_importances
    ]
    rows.sort(
        key=lambda row: (
            row["policy_name"],
            row["detector_name"],
            row["fold_name"],
            -row["absolute_value"],
        )
    )
    _write_csv(path, rows)
    return path


def _write_label_policy_sensitivity(result: CtuSupervisedEvaluationResult) -> Path:
    path = result.output_dir / "ctu_supervised_label_policy_sensitivity.csv"
    rows: list[dict[str, Any]] = []
    for policy_result in _policy_results(result):
        parsed_rows = sum(len(rows) for rows in policy_result.rows_by_scenario.values())
        for detector_result in policy_result.detector_results:
            matrix = detector_result.metrics.confusion_matrix
            rows.append(
                {
                    "story_stage": detector_result.story_stage,
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
                    "precision": detector_result.metrics.precision,
                    "recall": detector_result.metrics.recall,
                    "f1": detector_result.metrics.f1_score,
                    "false_positive_rate": detector_result.metrics.false_positive_rate,
                    "tp": matrix.true_positive,
                    "fp": matrix.false_positive,
                    "tn": matrix.true_negative,
                    "fn": matrix.false_negative,
                    "native_rows": parsed_rows,
                }
            )
    _write_csv(path, rows)
    return path


def _write_false_diagnostic(
    result: CtuSupervisedEvaluationResult,
    *,
    predicted_label: str,
    file_name: str,
) -> Path:
    path = result.output_dir / file_name
    rows: list[dict[str, Any]] = []
    target_true_label = "benign" if predicted_label == "beacon" else "beacon"
    count_name = "false_positive_count" if predicted_label == "beacon" else "false_negative_count"
    for policy_result in _policy_results(result):
        for detector_result in policy_result.detector_results:
            failures = [
                record
                for record in detector_result.records
                if record.true_label == target_true_label
                and record.predicted_label == predicted_label
            ]
            grouped: dict[tuple[str, str, str, int, str], list[CtuSupervisedPredictionRecord]] = {}
            for record in failures:
                key = (
                    record.test_scenario,
                    record.label_group,
                    record.protocol,
                    record.dst_port,
                    record.service_bucket,
                )
                grouped.setdefault(key, []).append(record)

            for (scenario, label_group, protocol, dst_port, service_bucket), records in sorted(
                grouped.items(), key=lambda item: len(item[1]), reverse=True
            ):
                rows.append(
                    {
                        "story_stage": detector_result.story_stage,
                        "policy_name": policy_result.policy_name,
                        "detector_name": detector_result.detector_name,
                        "operating_point": detector_result.operating_point,
                        "ctu_scenario": scenario,
                        "label_group": label_group,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "service_bucket": service_bucket,
                        count_name: len(records),
                        "mean_score": _mean([record.score for record in records]),
                        "mean_duration_seconds": _mean(
                            [record.duration_seconds for record in records]
                        ),
                        "mean_total_packets": _mean([record.total_packets for record in records]),
                        "mean_total_bytes": _mean([record.total_bytes for record in records]),
                        "mean_src_byte_ratio": _mean(
                            [
                                record.src_byte_ratio
                                for record in records
                                if record.src_byte_ratio is not None
                            ]
                        ),
                        "mean_packets_per_second": _mean(
                            [
                                record.packets_per_second
                                for record in records
                                if record.packets_per_second is not None
                            ]
                        ),
                    }
                )
    _write_csv(path, rows)
    return path


def _write_metadata(result: CtuSupervisedEvaluationResult) -> Path:
    path = result.output_dir / "ctu_supervised_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "CTU-13 bidirectional NetFlow",
        "story_stage": WITHIN_CTU_SUPERVISED_STAGE,
        "related_story_stages": [
            SYNTHETIC_TRANSFER_STAGE,
            CTU_NATIVE_UNSUPERVISED_STAGE,
            WITHIN_CTU_SUPERVISED_STAGE,
        ],
        "scenario_inputs": [
            {
                "scenario_name": scenario.scenario_name,
                "input_path": str(scenario.input_path),
                "max_rows": scenario.max_rows,
            }
            for scenario in result.scenarios
        ],
        "feature_path": "ctu_native",
        "feature_names": list(result.config.feature_names),
        "model_config": asdict(result.config),
        "primary_label_policy": asdict(result.conservative_result.label_policy),
        "split_strategy": "leave_one_ctu_scenario_out",
        "splits": [
            {
                "fold_name": split.fold_name,
                "train_scenarios": list(split.train_scenario_names),
                "test_scenario": split.test_scenario_name,
            }
            for split in result.conservative_result.splits
        ],
        "policy_results": [
            {
                "policy_name": policy_result.policy_name,
                "label_policy": asdict(policy_result.label_policy),
                "row_counts_by_scenario": {
                    scenario_name: len(rows)
                    for scenario_name, rows in policy_result.rows_by_scenario.items()
                },
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
            "This is within-CTU supervised evaluation, not synthetic direct transfer.",
            (
                "Conservative policy is the headline result; "
                "Background-as-benign is sensitivity analysis."
            ),
            "Scenario-aware folds test whether CTU-native models generalize across CTU captures.",
            "This does not make the project a production SOC detector.",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _policy_results(
    result: CtuSupervisedEvaluationResult,
) -> tuple[CtuSupervisedPolicyResult, ...]:
    if result.background_sensitivity_result is None:
        return (result.conservative_result,)
    return (result.conservative_result, result.background_sensitivity_result)


def _mean(values: list[float | int]) -> float | None:
    if not values:
        return None
    return float(sum(values) / len(values))


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
