"""Operational batch CLI for normalized flow scoring."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from glob import glob
from pathlib import Path

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.ops import (
    export_synthetic_normalized_csv,
    run_batch_score,
    train_random_forest_model,
    validate_normalized_csv,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run operational batch validation and beaconing scoring.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a canonical normalized CSV input file.",
    )
    validate_parser.add_argument("--input", required=True, type=Path)
    validate_parser.add_argument(
        "--require-label",
        action="store_true",
        help="Require a label column for model training input validation.",
    )
    validate_parser.add_argument("--label-column", default="label")

    export_parser = subparsers.add_parser(
        "export-synthetic",
        help="Export synthetic traffic into the labelled normalized CSV contract.",
    )
    export_parser.add_argument("--output", required=True, type=Path)
    export_parser.add_argument("--metadata-output", default=None, type=Path)
    export_parser.add_argument("--seed", default=7, type=int)
    export_parser.add_argument(
        "--start-time",
        default="2026-01-01T00:00:00+00:00",
        help="ISO-8601 synthetic start time.",
    )
    export_parser.add_argument("--normal-event-count", default=160, type=int)
    export_parser.add_argument("--normal-flow-count", default=6, type=int)
    export_parser.add_argument("--beacon-event-count", default=40, type=int)
    export_parser.add_argument("--duration-seconds", default=3600, type=int)
    export_parser.add_argument("--mean-interval-seconds", default=60.0, type=float)
    export_parser.add_argument("--jitter-fraction", default=0.35, type=float)
    export_parser.add_argument(
        "--exclude-time-size-jitter",
        action="store_true",
        help="Exclude the harder time-and-size-jittered synthetic beacon scenario.",
    )

    train_parser = subparsers.add_parser(
        "train-model",
        help="Train a Random Forest model from labelled normalized CSV input.",
    )
    train_parser.add_argument(
        "--train",
        action="append",
        required=True,
        help="Labelled normalized CSV path or glob. May be supplied multiple times.",
    )
    train_parser.add_argument("--label-column", default="label")
    train_parser.add_argument("--output-dir", required=True, type=Path)
    train_parser.add_argument(
        "--validation-folds",
        type=int,
        default=5,
        help="Requested StratifiedGroupKFold split count for grouped validation.",
    )

    score_parser = subparsers.add_parser(
        "score",
        help="Score a batch input and write operational outputs.",
    )
    score_parser.add_argument("--input", required=True, type=Path)
    score_parser.add_argument(
        "--input-format",
        required=True,
        choices=("normalized-csv", "zeek-conn"),
    )
    score_parser.add_argument("--output-dir", required=True, type=Path)
    score_parser.add_argument(
        "--model-artifact",
        type=Path,
        default=None,
        help="Optional operational RF model artifact directory or model.pkl file.",
    )

    args = parser.parse_args()
    if args.command == "validate":
        result = validate_normalized_csv(
            args.input,
            require_label=args.require_label,
            label_column=args.label_column,
        )
        print(f"input: {result.input_path}")
        print(f"rows: {result.row_count}")
        print(f"valid_rows: {result.valid_row_count}")
        print(f"issues: {len(result.issues)}")
        for issue in result.issues[:20]:
            location = (
                f"row {issue.row_number}" if issue.row_number is not None else "header"
            )
            column = f" column={issue.column}" if issue.column else ""
            print(f"- {location}{column}: {issue.message}")
        raise SystemExit(0 if result.is_valid else 1)

    if args.command == "export-synthetic":
        outputs = export_synthetic_normalized_csv(
            output_path=args.output,
            metadata_path=args.metadata_output,
            include_time_size_jitter=not args.exclude_time_size_jitter,
            config=SyntheticTrafficConfig(
                start_time=_parse_timestamp(args.start_time),
                seed=args.seed,
                normal_event_count=args.normal_event_count,
                normal_flow_count=args.normal_flow_count,
                beacon_event_count=args.beacon_event_count,
                duration_seconds=args.duration_seconds,
                mean_interval_seconds=args.mean_interval_seconds,
                jitter_fraction=args.jitter_fraction,
            ),
        )
        print("Synthetic normalized export complete")
        print(f"output_csv: {outputs.output_csv}")
        print(f"metadata_json: {outputs.metadata_json}")
        print(f"event_count: {outputs.event_count}")
        print(f"benign_event_count: {outputs.benign_event_count}")
        print(f"beacon_event_count: {outputs.beacon_event_count}")
        return

    if args.command == "train-model":
        outputs = train_random_forest_model(
            train_paths=_expand_train_paths(args.train),
            label_column=args.label_column,
            output_dir=args.output_dir,
            validation_folds=args.validation_folds,
        )
        print("Operational model training complete")
        print(f"model_dir: {outputs.model_dir}")
        print(f"model_file: {outputs.model_file}")
        print(f"metadata_json: {outputs.metadata_json}")
        print(f"artifact_manifest_json: {outputs.artifact_manifest_json}")
        print(f"training_summary_json: {outputs.training_summary_json}")
        print(f"training_report_md: {outputs.training_report_md}")
        return

    outputs = run_batch_score(
        input_path=args.input,
        input_format=args.input_format,
        output_dir=args.output_dir,
        model_artifact_path=args.model_artifact,
    )
    print("Operational scoring complete")
    print(f"alerts_csv: {outputs.alerts_csv}")
    print(f"scored_flows_csv: {outputs.scored_flows_csv}")
    print(f"run_summary_json: {outputs.run_summary_json}")
    print(f"report_md: {outputs.report_md}")


def _expand_train_paths(values: list[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        matches = sorted(glob(value))
        if matches:
            paths.extend(Path(match) for match in matches)
        else:
            paths.append(Path(value))
    return paths


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


if __name__ == "__main__":
    main()
