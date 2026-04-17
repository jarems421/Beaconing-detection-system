"""Score a supported dataset with a lightweight local detector interface."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from beacon_detector.evaluation.ctu13_supervised import (
    CTU_NATIVE_LOGISTIC_REGRESSION_NAME,
    CTU_NATIVE_RANDOM_FOREST_NAME,
    CtuSupervisedConfig,
    fit_ctu_native_supervised_detector,
    predict_ctu_native_supervised,
)
from beacon_detector.evaluation.metrics import calculate_classification_metrics
from beacon_detector.features.ctu_native import (
    Ctu13NativeFeatures,
    native_features_from_ctu13_records,
)
from beacon_detector.parsing import Ctu13LabelPolicy, load_ctu13_binetflow_events

DetectorChoice = Literal["ctu-native-logistic-regression", "ctu-native-random-forest"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score a CTU-13 .binetflow file with a local CTU-native detector.",
    )
    parser.add_argument("--input", required=True, type=Path, help="Input file to score.")
    parser.add_argument(
        "--input-format",
        required=True,
        choices=("ctu13-binetflow",),
        help="Supported input format.",
    )
    parser.add_argument(
        "--detector",
        required=True,
        choices=("ctu-native-logistic-regression", "ctu-native-random-forest"),
        help="Detector to train locally and use for scoring.",
    )
    parser.add_argument(
        "--train-scenario",
        action="append",
        required=True,
        help="Training scenario in the form scenario_name=path. May be supplied multiple times.",
    )
    parser.add_argument(
        "--scenario-name",
        default=None,
        help="Scenario name for the scored input. Defaults to the input file stem.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for scored CSV and summaries.",
    )
    parser.add_argument(
        "--include-background-as-benign",
        action="store_true",
        help="Use the Background-as-benign sensitivity policy for both training and scoring.",
    )
    args = parser.parse_args()

    outputs = score_ctu13_file(
        input_path=args.input,
        input_format=args.input_format,
        detector=args.detector,
        train_scenarios=dict(_parse_key_value(value) for value in args.train_scenario),
        output_dir=args.output_dir,
        scenario_name=args.scenario_name or args.input.stem,
        include_background_as_benign=args.include_background_as_benign,
    )

    print("Local detector scoring complete")
    for key, value in outputs.items():
        print(f"{key}: {value}")


def score_ctu13_file(
    *,
    input_path: Path,
    input_format: str,
    detector: DetectorChoice,
    train_scenarios: dict[str, Path],
    output_dir: Path,
    scenario_name: str,
    include_background_as_benign: bool = False,
    config: CtuSupervisedConfig | None = None,
) -> dict[str, Path]:
    if input_format != "ctu13-binetflow":
        raise ValueError(f"Unsupported input format: {input_format}")
    if not train_scenarios:
        raise ValueError("At least one training scenario is required.")

    label_policy = Ctu13LabelPolicy(include_background_as_benign=include_background_as_benign)
    config = config or CtuSupervisedConfig()
    training_rows: list[Ctu13NativeFeatures] = []
    for train_name, train_path in train_scenarios.items():
        training_rows.extend(
            _load_native_rows(train_path, scenario_name=train_name, label_policy=label_policy)
        )

    scoring_rows = _load_native_rows(
        input_path, scenario_name=scenario_name, label_policy=label_policy
    )
    detector_type = _detector_type(detector)
    model = fit_ctu_native_supervised_detector(
        training_rows,
        detector_type=detector_type,
        config=config,
    )
    predictions = predict_ctu_native_supervised(scoring_rows, model=model)

    output_dir.mkdir(parents=True, exist_ok=True)
    scored_path = output_dir / "scored_flows.csv"
    summary_json_path = output_dir / "summary.json"
    summary_markdown_path = output_dir / "summary.md"

    rows = [_scored_row(row, score, predicted_label) for row, score, predicted_label in predictions]
    _write_csv(scored_path, rows)
    metrics = calculate_classification_metrics(
        [row.label for row, _, _ in predictions],
        [predicted_label for _, _, predicted_label in predictions],
    )
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_path": str(input_path),
        "input_format": input_format,
        "scenario_name": scenario_name,
        "detector": detector,
        "detector_name": model.detector_name,
        "threshold": config.prediction_threshold,
        "label_policy": asdict(label_policy),
        "train_scenarios": {name: str(path) for name, path in train_scenarios.items()},
        "training_rows": len(training_rows),
        "scored_rows": len(scoring_rows),
        "metrics": {
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1_score,
            "false_positive_rate": metrics.false_positive_rate,
            "tp": metrics.confusion_matrix.true_positive,
            "fp": metrics.confusion_matrix.false_positive,
            "tn": metrics.confusion_matrix.true_negative,
            "fn": metrics.confusion_matrix.false_negative,
        },
        "notes": [
            "This is a lightweight local scorer for supported CTU-13 .binetflow files.",
            "It trains from explicit CTU training scenarios supplied on the command line.",
            "It is not a live monitor, dashboard, or production SOC detector.",
        ],
    }
    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary_markdown_path.write_text(_summary_markdown(summary), encoding="utf-8")

    return {
        "scored_csv": scored_path,
        "summary_json": summary_json_path,
        "summary_md": summary_markdown_path,
    }


def _load_native_rows(
    input_path: Path,
    *,
    scenario_name: str,
    label_policy: Ctu13LabelPolicy,
) -> list[Ctu13NativeFeatures]:
    load_result = load_ctu13_binetflow_events(
        input_path,
        scenario_name=scenario_name,
        label_policy=label_policy,
    )
    return native_features_from_ctu13_records(load_result.records, scenario_name=scenario_name)


def _detector_type(detector: DetectorChoice) -> Literal["logistic_regression", "random_forest"]:
    if detector == "ctu-native-logistic-regression":
        return "logistic_regression"
    if detector == "ctu-native-random-forest":
        return "random_forest"
    raise ValueError(f"Unsupported detector: {detector}")


def _scored_row(row: Ctu13NativeFeatures, score: float, predicted_label: str) -> dict[str, Any]:
    return {
        "scenario_name": row.scenario_name,
        "label_group": row.label_group,
        "true_label": row.label,
        "predicted_label": predicted_label,
        "score": score,
        "protocol": row.protocol,
        "dst_port": row.dst_port,
        "service_bucket": row.service_bucket,
        "duration_seconds": row.duration_seconds,
        "total_packets": row.total_packets,
        "total_bytes": row.total_bytes,
        "src_bytes": row.src_bytes,
        "dst_bytes": row.dst_bytes,
        "src_byte_ratio": row.src_byte_ratio,
        "dst_byte_ratio": row.dst_byte_ratio,
        "packets_per_second": row.packets_per_second,
        "bytes_per_second": row.bytes_per_second,
    }


def _summary_markdown(summary: dict[str, Any]) -> str:
    metrics = summary["metrics"]
    detector_name = (
        CTU_NATIVE_LOGISTIC_REGRESSION_NAME
        if summary["detector"] == "ctu-native-logistic-regression"
        else CTU_NATIVE_RANDOM_FOREST_NAME
    )
    return "\n".join(
        [
            "# Local Detector Scoring Summary",
            "",
            f"- Input: `{summary['input_path']}`",
            f"- Detector: `{detector_name}`",
            f"- Scenario: `{summary['scenario_name']}`",
            f"- Training rows: {summary['training_rows']}",
            f"- Scored rows: {summary['scored_rows']}",
            f"- Precision: {metrics['precision']:.3f}",
            f"- Recall: {metrics['recall']:.3f}",
            f"- F1: {metrics['f1']:.3f}",
            f"- False-positive rate: {metrics['false_positive_rate']:.3f}",
            "",
            "This is a local research scorer, not a production SOC detector.",
            "",
        ]
    )


def _parse_key_value(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("Expected value in the form name=path")
    key, path = value.split("=", maxsplit=1)
    return key.strip(), Path(path.strip())


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


if __name__ == "__main__":
    main()
