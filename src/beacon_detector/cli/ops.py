"""Operational batch CLI for normalized flow scoring."""

from __future__ import annotations

import argparse
from glob import glob
from pathlib import Path

from beacon_detector.ops import (
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


if __name__ == "__main__":
    main()
