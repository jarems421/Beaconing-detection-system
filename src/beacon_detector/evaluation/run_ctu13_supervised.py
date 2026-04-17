"""Command-line entrypoint for within-CTU supervised evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .ctu13 import Ctu13ScenarioInput
from .ctu13_supervised import (
    export_ctu_supervised_tables,
    run_ctu_supervised_evaluation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run within-CTU supervised evaluation on CTU-native features.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        required=True,
        help="Scenario input in the form scenario_name=path. May be supplied multiple times.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/tables/ctu13_supervised"),
        help="Directory for CTU supervised outputs.",
    )
    parser.add_argument(
        "--no-background-sensitivity",
        action="store_true",
        help="Skip the separate Background-as-benign sensitivity analysis.",
    )
    args = parser.parse_args()

    scenarios = [_parse_scenario_arg(value) for value in args.scenario]
    result = run_ctu_supervised_evaluation(
        scenarios=scenarios,
        output_dir=args.output_dir,
        include_background_sensitivity=not args.no_background_sensitivity,
    )
    written_paths = export_ctu_supervised_tables(result)

    print("Within-CTU supervised evaluation complete")
    for policy_result in (result.conservative_result, result.background_sensitivity_result):
        if policy_result is None:
            continue
        print(f"policy={policy_result.policy_name}")
        for detector_result in policy_result.detector_results:
            metrics = detector_result.metrics
            print(
                f"  {detector_result.detector_name}: "
                f"precision={metrics.precision:.3f} "
                f"recall={metrics.recall:.3f} "
                f"f1={metrics.f1_score:.3f} "
                f"fpr={metrics.false_positive_rate:.3f}"
            )
    print("written files:")
    for path in written_paths:
        print(path)


def _parse_scenario_arg(value: str) -> Ctu13ScenarioInput:
    if "=" not in value:
        raise ValueError("--scenario must use the form scenario_name=path")
    scenario_name, path = value.split("=", maxsplit=1)
    return Ctu13ScenarioInput(
        scenario_name=scenario_name.strip(),
        input_path=Path(path.strip()),
    )


if __name__ == "__main__":
    main()
