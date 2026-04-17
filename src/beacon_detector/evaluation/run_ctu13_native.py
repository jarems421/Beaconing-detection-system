"""Command-line entrypoint for CTU-native feature-path comparison."""

from __future__ import annotations

import argparse
from pathlib import Path

from .ctu13 import Ctu13ScenarioInput
from .ctu13_native import (
    export_ctu_native_comparison_tables,
    run_ctu_native_feature_comparison,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare transferred FlowFeatures with CTU-native feature adaptation.",
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
        default=Path("results/tables/ctu13_native"),
        help="Directory for CTU-native comparison outputs.",
    )
    args = parser.parse_args()

    scenarios = [_parse_scenario_arg(value) for value in args.scenario]
    result = run_ctu_native_feature_comparison(
        scenarios=scenarios,
        output_dir=args.output_dir,
    )
    written_paths = export_ctu_native_comparison_tables(result)

    print("CTU-native feature comparison complete")
    for detector_result in result.detector_results:
        metrics = detector_result.metrics
        if metrics is None:
            print(
                f"{detector_result.detector_name}: "
                f"{detector_result.compatibility_status}"
            )
        else:
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
