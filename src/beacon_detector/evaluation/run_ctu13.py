"""Command-line entrypoint for CTU-13 public dataset evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path

from beacon_detector.parsing import Ctu13LabelPolicy

from .ctu13 import (
    Ctu13EvaluationConfig,
    Ctu13ScenarioInput,
    export_ctu13_evaluation_tables,
    export_ctu13_multi_scenario_tables,
    run_ctu13_evaluation,
    run_ctu13_multi_scenario_evaluation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the existing beacon detectors on CTU-13 bidirectional flow data.",
    )
    parser.add_argument("--input", type=Path, help="Path to a .binetflow file.")
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help=(
            "Multi-scenario input in the form scenario_name=path. "
            "May be supplied multiple times. If provided, --input is ignored."
        ),
    )
    parser.add_argument(
        "--scenario-name",
        default="ctu13_scenario",
        help="Name to use for this CTU-13 capture in exports.",
    )
    parser.add_argument(
        "--output-dir",
        default=Path("results/tables/ctu13"),
        type=Path,
        help="Directory for CTU-13 CSV/JSON exports.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional row cap for adapter smoke tests.",
    )
    parser.add_argument(
        "--include-background-as-benign",
        action="store_true",
        help="Map CTU-13 Background labels to benign instead of excluding them.",
    )
    parser.add_argument(
        "--skip-background-sensitivity",
        action="store_true",
        help="For multi-scenario mode, skip the separate background-as-benign sensitivity run.",
    )
    args = parser.parse_args()

    if args.scenario:
        scenarios = [_parse_scenario_arg(value, max_rows=args.max_rows) for value in args.scenario]
        result = run_ctu13_multi_scenario_evaluation(
            scenarios=scenarios,
            output_dir=args.output_dir,
            include_background_sensitivity=not args.skip_background_sensitivity,
        )
        written_paths = export_ctu13_multi_scenario_tables(result)
        _print_multi_summary(result, written_paths)
        return

    if args.input is None:
        parser.error("--input is required unless one or more --scenario values are provided.")

    config = Ctu13EvaluationConfig(
        input_path=args.input,
        scenario_name=args.scenario_name,
        output_dir=args.output_dir,
        max_rows=args.max_rows,
        label_policy=Ctu13LabelPolicy(
            include_background_as_benign=args.include_background_as_benign,
        ),
    )
    result = run_ctu13_evaluation(config)
    written_paths = export_ctu13_evaluation_tables(result)

    print("CTU-13 evaluation complete")
    print(f"feature rows: {len(result.dataset.feature_rows)}")
    print(f"evaluation rows: {len(result.dataset.evaluation_rows)}")
    print(f"reference benign rows: {len(result.dataset.reference_benign_rows)}")
    for detector_result in result.detector_results:
        metrics = detector_result.metrics
        print(
            f"{detector_result.detector_name}: "
            f"precision={metrics.precision:.3f} "
            f"recall={metrics.recall:.3f} "
            f"f1={metrics.f1_score:.3f} "
            f"fpr={metrics.false_positive_rate:.3f}"
        )
    print("written files:")
    for path in written_paths:
        print(path)


def _parse_scenario_arg(value: str, *, max_rows: int | None) -> Ctu13ScenarioInput:
    if "=" not in value:
        raise ValueError("--scenario must use the form scenario_name=path")
    scenario_name, path = value.split("=", maxsplit=1)
    return Ctu13ScenarioInput(
        scenario_name=scenario_name.strip(),
        input_path=Path(path.strip()),
        max_rows=max_rows,
    )


def _print_multi_summary(result, written_paths) -> None:
    print("CTU-13 multi-scenario evaluation complete")
    print("scenarios:")
    for scenario in result.scenario_inputs:
        print(f"- {scenario.scenario_name}: {scenario.input_path}")
    for policy_result in (
        result.conservative_result,
        result.background_sensitivity_result,
    ):
        if policy_result is None:
            continue
        print(f"policy: {policy_result.policy_name}")
        for detector_result in policy_result.detector_results:
            metrics = detector_result.metrics
            print(
                f"{detector_result.detector_name}: "
                f"precision={metrics.precision:.3f} "
                f"recall={metrics.recall:.3f} "
                f"f1={metrics.f1_score:.3f} "
                f"fpr={metrics.false_positive_rate:.3f}"
            )
    print("written files:")
    for path in written_paths:
        print(path)


if __name__ == "__main__":
    main()
