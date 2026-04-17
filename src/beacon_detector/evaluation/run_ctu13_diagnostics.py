"""Command-line entrypoint for CTU-13 feature-distribution diagnostics."""

from __future__ import annotations

import argparse
from pathlib import Path

from .ctu13_diagnostics import (
    Ctu13DiagnosticScenario,
    export_ctu13_feature_diagnostic_tables,
    run_ctu13_feature_diagnostic,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compare synthetic and CTU-13 feature distributions without rerunning detectors."
        ),
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="Scenario input in the form scenario_name=path. May be supplied multiple times.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/tables/ctu13_feature_diagnostic"),
        help="Directory for diagnostic CSV/JSON outputs.",
    )
    args = parser.parse_args()

    scenarios = [_parse_scenario_arg(value) for value in args.scenario] or None
    result = run_ctu13_feature_diagnostic(
        scenarios=scenarios,
        output_dir=args.output_dir,
    )
    written_paths = export_ctu13_feature_diagnostic_tables(result)

    print("CTU-13 feature diagnostic complete")
    for path in written_paths:
        print(path)


def _parse_scenario_arg(value: str) -> Ctu13DiagnosticScenario:
    if "=" not in value:
        raise ValueError("--scenario must use the form scenario_name=path")
    scenario_name, path = value.split("=", maxsplit=1)
    return Ctu13DiagnosticScenario(
        scenario_name=scenario_name.strip(),
        input_path=Path(path.strip()),
    )


if __name__ == "__main__":
    main()
