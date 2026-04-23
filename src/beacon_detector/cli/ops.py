"""Operational batch CLI for normalized flow scoring."""

from __future__ import annotations

import argparse
from pathlib import Path

from beacon_detector.ops import run_rules_only_score, validate_normalized_csv


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

    args = parser.parse_args()
    if args.command == "validate":
        result = validate_normalized_csv(args.input)
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

    outputs = run_rules_only_score(
        input_path=args.input,
        input_format=args.input_format,
        output_dir=args.output_dir,
    )
    print("Operational scoring complete")
    print(f"alerts_csv: {outputs.alerts_csv}")
    print(f"scored_flows_csv: {outputs.scored_flows_csv}")
    print(f"run_summary_json: {outputs.run_summary_json}")
    print(f"report_md: {outputs.report_md}")


if __name__ == "__main__":
    main()
