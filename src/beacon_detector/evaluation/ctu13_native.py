"""CTU-native feature-path comparison for public-data validation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from beacon_detector.features.ctu_native import (
    CTU13_NATIVE_NUMERIC_FEATURES,
    Ctu13NativeFeatures,
    native_features_from_ctu13_records,
)
from beacon_detector.parsing import Ctu13LabelPolicy, load_ctu13_binetflow_events

from .ctu13 import Ctu13ScenarioInput
from .metrics import ClassificationMetrics, calculate_classification_metrics


@dataclass(frozen=True, slots=True)
class CtuNativeDetectorResult:
    detector_name: str
    operating_point: str
    feature_path: str
    compatibility_status: str
    compatibility_notes: str
    metrics: ClassificationMetrics | None
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class CtuNativeComparisonResult:
    scenarios: tuple[Ctu13ScenarioInput, ...]
    output_dir: Path
    conservative_rows: tuple[Ctu13NativeFeatures, ...]
    background_rows: tuple[Ctu13NativeFeatures, ...]
    detector_results: tuple[CtuNativeDetectorResult, ...]
    transferred_result_path: Path | None


def run_ctu_native_feature_comparison(
    *,
    scenarios: list[Ctu13ScenarioInput],
    output_dir: str | Path = "results/tables/ctu13_native",
    transferred_result_path: str | Path | None = (
        "results/tables/ctu13_multi/ctu13_multi_scenario_detector_comparison.csv"
    ),
    benign_reference_fraction: float = 0.5,
) -> CtuNativeComparisonResult:
    conservative_rows = _load_native_rows(
        scenarios,
        label_policy=Ctu13LabelPolicy(),
    )
    background_rows = _load_native_rows(
        scenarios,
        label_policy=Ctu13LabelPolicy(include_background_as_benign=True),
    )
    detector_results = _evaluate_native_detectors(
        conservative_rows,
        benign_reference_fraction=benign_reference_fraction,
    )
    return CtuNativeComparisonResult(
        scenarios=tuple(scenarios),
        output_dir=Path(output_dir),
        conservative_rows=tuple(conservative_rows),
        background_rows=tuple(background_rows),
        detector_results=tuple(detector_results),
        transferred_result_path=Path(transferred_result_path)
        if transferred_result_path
        else None,
    )


def export_ctu_native_comparison_tables(
    result: CtuNativeComparisonResult,
) -> list[Path]:
    result.output_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write_native_feature_summary(result),
        _write_native_detector_comparison(result),
        _write_native_per_scenario_metrics(result),
        _write_feature_path_comparison(result),
        _write_native_metadata(result),
    ]


def _load_native_rows(
    scenarios: list[Ctu13ScenarioInput],
    *,
    label_policy: Ctu13LabelPolicy,
) -> list[Ctu13NativeFeatures]:
    rows: list[Ctu13NativeFeatures] = []
    for scenario in scenarios:
        load_result = load_ctu13_binetflow_events(
            scenario.input_path,
            scenario_name=scenario.scenario_name,
            label_policy=label_policy,
            max_rows=scenario.max_rows,
        )
        rows.extend(
            native_features_from_ctu13_records(
                load_result.records,
                scenario_name=scenario.scenario_name,
            )
        )
    return rows


def _evaluate_native_detectors(
    rows: list[Ctu13NativeFeatures],
    *,
    benign_reference_fraction: float,
) -> list[CtuNativeDetectorResult]:
    reference_rows, evaluation_rows = _split_reference_and_evaluation_rows(
        rows,
        benign_reference_fraction=benign_reference_fraction,
    )
    results = [
        _incompatible_result(
            "rule_baseline_v2_hardened_final",
            "threshold=2.8",
            (
                "Rule baseline depends on synthetic FlowFeatures such as inter-arrival "
                "and burst fields; applying it to CTU-native fields would be a fake comparison."
            ),
        ),
        _evaluate_native_lof(reference_rows, evaluation_rows),
        _incompatible_result(
            "rf_full_threshold_0p6",
            "synthetic_training;threshold=0.6;features=full",
            (
                "Synthetic-trained RF expects the FlowFeatures schema. CTU-native fields "
                "have different meanings and cannot be scored without retraining or a fake mapping."
            ),
        ),
        _incompatible_result(
            "rf_full_threshold_0p3",
            "synthetic_training;threshold=0.3;features=full",
            (
                "Synthetic-trained RF expects the FlowFeatures schema. CTU-native fields "
                "have different meanings and cannot be scored without retraining or a fake mapping."
            ),
        ),
    ]
    return results


def _evaluate_native_lof(
    reference_rows: list[Ctu13NativeFeatures],
    evaluation_rows: list[Ctu13NativeFeatures],
) -> CtuNativeDetectorResult:
    if len(reference_rows) < 2:
        raise ValueError("Native CTU LOF requires at least two benign reference rows.")

    scaler = StandardScaler()
    reference_matrix = _native_feature_matrix(reference_rows)
    evaluation_matrix = _native_feature_matrix(evaluation_rows)
    scaled_reference = scaler.fit_transform(reference_matrix)
    scaled_evaluation = scaler.transform(evaluation_matrix)
    estimator = LocalOutlierFactor(n_neighbors=20, contamination=0.03, novelty=True)
    estimator.fit(scaled_reference)
    scores = [-float(score) for score in estimator.decision_function(scaled_evaluation)]

    records: list[dict[str, Any]] = []
    for row, score in zip(evaluation_rows, scores, strict=False):
        predicted_label = "beacon" if score >= 0.0 else "benign"
        records.append(
            {
                "scenario_name": row.scenario_name,
                "label_group": row.label_group,
                "true_label": row.label,
                "predicted_label": predicted_label,
                "score": score,
                "protocol": row.protocol,
                "dst_port": row.dst_port,
                "service_bucket": row.service_bucket,
            }
        )

    metrics = calculate_classification_metrics(
        [record["true_label"] for record in records],
        [record["predicted_label"] for record in records],
    )
    return CtuNativeDetectorResult(
        detector_name="local_outlier_factor_v1",
        operating_point="ctu_native_benign_reference;contamination=0.03",
        feature_path="ctu_native",
        compatibility_status="compatible_unsupervised_reference",
        compatibility_notes=(
            "LOF can use CTU-native numeric fields with a held-out benign CTU reference. "
            "This is still not supervised CTU training."
        ),
        metrics=metrics,
        records=tuple(records),
    )


def _incompatible_result(
    detector_name: str,
    operating_point: str,
    notes: str,
) -> CtuNativeDetectorResult:
    return CtuNativeDetectorResult(
        detector_name=detector_name,
        operating_point=operating_point,
        feature_path="ctu_native",
        compatibility_status="not_schema_compatible",
        compatibility_notes=notes,
        metrics=None,
        records=(),
    )


def _split_reference_and_evaluation_rows(
    rows: list[Ctu13NativeFeatures],
    *,
    benign_reference_fraction: float,
) -> tuple[list[Ctu13NativeFeatures], list[Ctu13NativeFeatures]]:
    benign_rows = [row for row in rows if row.label == "benign"]
    beacon_rows = [row for row in rows if row.label == "beacon"]
    if len(benign_rows) < 2:
        raise ValueError("At least two benign CTU-native rows are required.")
    reference_count = max(2, int(len(benign_rows) * benign_reference_fraction))
    reference_count = min(reference_count, len(benign_rows))
    return benign_rows[:reference_count], benign_rows[reference_count:] + beacon_rows


def _native_feature_matrix(rows: list[Ctu13NativeFeatures]) -> list[list[float]]:
    return [
        [
            _native_feature_value(row, feature_name)
            for feature_name in CTU13_NATIVE_NUMERIC_FEATURES
        ]
        for row in rows
    ]


def _native_feature_value(row: Ctu13NativeFeatures, feature_name: str) -> float:
    value = getattr(row, feature_name)
    if value is None:
        return 0.0
    return float(value)


def _write_native_feature_summary(result: CtuNativeComparisonResult) -> Path:
    path = result.output_dir / "ctu_native_feature_summary.csv"
    rows: list[dict[str, Any]] = []
    for policy_name, feature_rows in (
        ("conservative", result.conservative_rows),
        ("background_as_benign_sensitivity", result.background_rows),
    ):
        for group_name in _native_group_names(feature_rows):
            group_rows = [row for row in feature_rows if _native_group_name(row) == group_name]
            for scenario_name in ["pooled", *_scenario_names(group_rows)]:
                scenario_rows = (
                    group_rows
                    if scenario_name == "pooled"
                    else [row for row in group_rows if row.scenario_name == scenario_name]
                )
                if not scenario_rows:
                    continue
                for feature_name in CTU13_NATIVE_NUMERIC_FEATURES:
                    rows.append(
                        {
                            "policy_name": policy_name,
                            "group_name": group_name,
                            "scenario_name": scenario_name,
                            "feature_name": feature_name,
                            **_numeric_summary(
                                [
                                    _native_feature_value(row, feature_name)
                                    for row in scenario_rows
                                ]
                            ),
                        }
                    )
    _write_csv(path, rows)
    return path


def _write_native_detector_comparison(result: CtuNativeComparisonResult) -> Path:
    path = result.output_dir / "ctu_native_detector_comparison.csv"
    rows: list[dict[str, Any]] = []
    for detector_result in result.detector_results:
        metrics = detector_result.metrics
        matrix = metrics.confusion_matrix if metrics else None
        rows.append(
            {
                "feature_path": detector_result.feature_path,
                "detector_name": detector_result.detector_name,
                "operating_point": detector_result.operating_point,
                "compatibility_status": detector_result.compatibility_status,
                "compatibility_notes": detector_result.compatibility_notes,
                "precision": metrics.precision if metrics else "",
                "recall": metrics.recall if metrics else "",
                "f1": metrics.f1_score if metrics else "",
                "false_positive_rate": metrics.false_positive_rate if metrics else "",
                "tp": matrix.true_positive if matrix else "",
                "fp": matrix.false_positive if matrix else "",
                "tn": matrix.true_negative if matrix else "",
                "fn": matrix.false_negative if matrix else "",
            }
        )
    _write_csv(path, rows)
    return path


def _write_native_per_scenario_metrics(result: CtuNativeComparisonResult) -> Path:
    path = result.output_dir / "ctu_native_per_scenario_metrics.csv"
    rows: list[dict[str, Any]] = []
    for detector_result in result.detector_results:
        if detector_result.metrics is None:
            continue
        scenario_names = sorted({record["scenario_name"] for record in detector_result.records})
        for scenario_name in scenario_names:
            scenario_records = [
                record
                for record in detector_result.records
                if record["scenario_name"] == scenario_name
            ]
            metrics = calculate_classification_metrics(
                [record["true_label"] for record in scenario_records],
                [record["predicted_label"] for record in scenario_records],
            )
            matrix = metrics.confusion_matrix
            rows.append(
                {
                    "feature_path": detector_result.feature_path,
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


def _write_feature_path_comparison(result: CtuNativeComparisonResult) -> Path:
    path = result.output_dir / "ctu_feature_path_comparison.csv"
    rows: list[dict[str, Any]] = []
    rows.extend(_transferred_rows(result.transferred_result_path))
    for detector_result in result.detector_results:
        metrics = detector_result.metrics
        matrix = metrics.confusion_matrix if metrics else None
        rows.append(
            {
                "feature_path": "ctu_native",
                "policy_name": "conservative",
                "detector_name": detector_result.detector_name,
                "operating_point": detector_result.operating_point,
                "compatibility_status": detector_result.compatibility_status,
                "precision": metrics.precision if metrics else "",
                "recall": metrics.recall if metrics else "",
                "f1": metrics.f1_score if metrics else "",
                "false_positive_rate": metrics.false_positive_rate if metrics else "",
                "tp": matrix.true_positive if matrix else "",
                "fp": matrix.false_positive if matrix else "",
                "tn": matrix.true_negative if matrix else "",
                "fn": matrix.false_negative if matrix else "",
            }
        )
    _write_csv(path, rows)
    return path


def _transferred_rows(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as input_file:
        for row in csv.DictReader(input_file):
            if row.get("policy_name") != "conservative":
                continue
            rows.append(
                {
                    "feature_path": "transferred_flowfeatures",
                    "policy_name": row.get("policy_name", ""),
                    "detector_name": row.get("detector_name", ""),
                    "operating_point": row.get("operating_point", ""),
                    "compatibility_status": "compatible_existing_transfer_path",
                    "precision": row.get("precision", ""),
                    "recall": row.get("recall", ""),
                    "f1": row.get("f1", ""),
                    "false_positive_rate": row.get("false_positive_rate", ""),
                    "tp": row.get("tp", ""),
                    "fp": row.get("fp", ""),
                    "tn": row.get("tn", ""),
                    "fn": row.get("fn", ""),
                }
            )
    return rows


def _write_native_metadata(result: CtuNativeComparisonResult) -> Path:
    path = result.output_dir / "ctu_native_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Compare transferred FlowFeatures path against CTU-native feature adaptation.",
        "scenario_inputs": [
            {
                "scenario_name": scenario.scenario_name,
                "input_path": str(scenario.input_path),
                "max_rows": scenario.max_rows,
            }
            for scenario in result.scenarios
        ],
        "native_numeric_features": list(CTU13_NATIVE_NUMERIC_FEATURES),
        "conservative_row_count": len(result.conservative_rows),
        "background_sensitivity_row_count": len(result.background_rows),
        "transferred_result_path": str(result.transferred_result_path)
        if result.transferred_result_path
        else None,
        "compatibility_notes": [
            "CTU-native features are separate from synthetic FlowFeatures.",
            (
                "Rule baseline and synthetic-trained RF are not scored on CTU-native fields "
                "because their feature schemas are not compatible without changing detector logic "
                "or retraining."
            ),
            (
                "LOF is evaluated on CTU-native numeric fields using a held-out benign CTU "
                "reference because it is an unsupervised/reference detector."
            ),
            "No within-CTU supervised evaluation is performed in this step.",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _native_group_names(rows: tuple[Ctu13NativeFeatures, ...]) -> list[str]:
    preferred = ["ctu_from_normal", "ctu_background", "ctu_from_botnet"]
    available = {_native_group_name(row) for row in rows}
    return [name for name in preferred if name in available]


def _native_group_name(row: Ctu13NativeFeatures) -> str:
    if row.label_group == "ctu13_from_botnet":
        return "ctu_from_botnet"
    if row.label_group == "ctu13_from_normal":
        return "ctu_from_normal"
    if row.label_group == "ctu13_background":
        return "ctu_background"
    return "ctu_other"


def _scenario_names(rows: list[Ctu13NativeFeatures]) -> list[str]:
    return sorted({row.scenario_name for row in rows})


def _numeric_summary(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "p25": None,
            "p75": None,
            "min": None,
            "max": None,
        }
    return {
        "count": len(ordered),
        "mean": sum(ordered) / len(ordered),
        "median": float(median(ordered)),
        "p25": _quantile(ordered, 0.25),
        "p75": _quantile(ordered, 0.75),
        "min": ordered[0],
        "max": ordered[-1],
    }


def _quantile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + ((values[upper] - values[lower]) * fraction)


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
