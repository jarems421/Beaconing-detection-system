"""CTU-13 feature-distribution diagnostics for synthetic-to-public transfer."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import build_flows
from beacon_detector.parsing import Ctu13LabelPolicy, load_ctu13_binetflow_events

from .cache import FEATURE_SCHEMA_VERSION, FeatureCacheConfig
from .runner import (
    SUPERVISED_TRAINING_SEEDS,
    build_case_feature_rows,
    build_default_evaluation_grid,
)

DIAGNOSTIC_NUMERIC_FEATURES = (
    "event_count",
    "flow_duration_seconds",
    "total_bytes",
    "size_cv",
    "normalized_size_range",
    "size_bin_count",
    "dominant_size_bin_fraction",
    "interarrival_iqr_seconds",
    "interarrival_mad_seconds",
    "gap_range_median_ratio",
    "near_median_interarrival_fraction",
    "interarrival_within_20pct_median_fraction",
    "dominant_interval_bin_fraction",
)


@dataclass(frozen=True, slots=True)
class Ctu13DiagnosticScenario:
    scenario_name: str
    input_path: Path
    max_rows: int | None = None


@dataclass(frozen=True, slots=True)
class DiagnosticFeatureRecord:
    group_name: str
    source_family: str
    ctu_scenario: str | None
    feature_row: FlowFeatures


@dataclass(frozen=True, slots=True)
class Ctu13FeatureDiagnosticResult:
    records: tuple[DiagnosticFeatureRecord, ...]
    scenarios: tuple[Ctu13DiagnosticScenario, ...]
    synthetic_seeds: tuple[int, ...]
    output_dir: Path


def default_ctu13_diagnostic_scenarios() -> list[Ctu13DiagnosticScenario]:
    return [
        Ctu13DiagnosticScenario(
            scenario_name="ctu13_scenario_5",
            input_path=Path("data/public/ctu13/scenario_5/capture20110815-2.binetflow"),
        ),
        Ctu13DiagnosticScenario(
            scenario_name="ctu13_scenario_7",
            input_path=Path("data/public/ctu13/scenario_7/capture20110816-2.binetflow"),
        ),
        Ctu13DiagnosticScenario(
            scenario_name="ctu13_scenario_11",
            input_path=Path("data/public/ctu13/scenario_11/capture20110818-2.binetflow"),
        ),
    ]


def run_ctu13_feature_diagnostic(
    *,
    scenarios: list[Ctu13DiagnosticScenario] | None = None,
    synthetic_seeds: tuple[int, ...] = (SUPERVISED_TRAINING_SEEDS[0],),
    output_dir: str | Path = "results/tables/ctu13_feature_diagnostic",
    cache_config: FeatureCacheConfig | None = None,
) -> Ctu13FeatureDiagnosticResult:
    scenarios = scenarios or default_ctu13_diagnostic_scenarios()
    records: list[DiagnosticFeatureRecord] = []
    records.extend(_synthetic_records(synthetic_seeds, cache_config=cache_config))
    records.extend(_ctu_records(scenarios))
    return Ctu13FeatureDiagnosticResult(
        records=tuple(records),
        scenarios=tuple(scenarios),
        synthetic_seeds=tuple(synthetic_seeds),
        output_dir=Path(output_dir),
    )


def export_ctu13_feature_diagnostic_tables(
    result: Ctu13FeatureDiagnosticResult,
) -> list[Path]:
    result.output_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write_distribution_summary(result),
        _write_shift_ranking(result),
        _write_protocol_port_summary(result),
        _write_metadata(result),
    ]


def ctu13_diagnostic_group_name(row: FlowFeatures, *, source_family: str) -> str:
    if source_family == "synthetic":
        return "synthetic_beacon" if row.label == "beacon" else "synthetic_benign"

    scenario_name = row.scenario_name or ""
    if "ctu13_from_botnet" in scenario_name:
        return "ctu_from_botnet"
    if "ctu13_from_normal" in scenario_name:
        return "ctu_from_normal"
    if "ctu13_background" in scenario_name:
        return "ctu_background"
    return "ctu_other"


def _synthetic_records(
    synthetic_seeds: tuple[int, ...],
    *,
    cache_config: FeatureCacheConfig | None,
) -> list[DiagnosticFeatureRecord]:
    records: list[DiagnosticFeatureRecord] = []
    template_cases = build_default_evaluation_grid()
    for seed in synthetic_seeds:
        for case in template_cases:
            seeded_case = _replace_case_seed(case, seed)
            for row in build_case_feature_rows(seeded_case, cache_config=cache_config):
                records.append(
                    DiagnosticFeatureRecord(
                        group_name=ctu13_diagnostic_group_name(
                            row,
                            source_family="synthetic",
                        ),
                        source_family="synthetic",
                        ctu_scenario=None,
                        feature_row=row,
                    )
                )
    return records


def _ctu_records(
    scenarios: list[Ctu13DiagnosticScenario],
) -> list[DiagnosticFeatureRecord]:
    records: list[DiagnosticFeatureRecord] = []
    policy = Ctu13LabelPolicy(include_background_as_benign=True)
    for scenario in scenarios:
        load_result = load_ctu13_binetflow_events(
            scenario.input_path,
            scenario_name=scenario.scenario_name,
            label_policy=policy,
            max_rows=scenario.max_rows,
        )
        rows = extract_features_from_flows(build_flows(load_result.events))
        for row in rows:
            group_name = ctu13_diagnostic_group_name(row, source_family="ctu")
            if group_name == "ctu_other":
                continue
            records.append(
                DiagnosticFeatureRecord(
                    group_name=group_name,
                    source_family="ctu",
                    ctu_scenario=scenario.scenario_name,
                    feature_row=row,
                )
            )
    return records


def _replace_case_seed(case, seed: int):
    from dataclasses import replace

    return replace(
        case,
        config=replace(case.config, seed=seed),
    )


def _write_distribution_summary(result: Ctu13FeatureDiagnosticResult) -> Path:
    path = result.output_dir / "ctu_feature_distribution_summary.csv"
    rows: list[dict[str, Any]] = []
    for group_name in _group_names(result.records):
        group_records = [record for record in result.records if record.group_name == group_name]
        for scenario_name, scenario_records in _scenario_slices(group_records):
            for feature_name in DIAGNOSTIC_NUMERIC_FEATURES:
                values = [
                    _feature_value(record.feature_row, feature_name)
                    for record in scenario_records
                ]
                rows.append(
                    {
                        "group_name": group_name,
                        "source_family": scenario_records[0].source_family
                        if scenario_records
                        else "",
                        "ctu_scenario": scenario_name,
                        "feature_name": feature_name,
                        **_numeric_summary(values),
                    }
                )
    _write_csv(path, rows)
    return path


def _write_shift_ranking(result: Ctu13FeatureDiagnosticResult) -> Path:
    path = result.output_dir / "ctu_feature_shift_ranking.csv"
    comparisons = (
        ("synthetic_benign_vs_ctu_from_normal", "synthetic_benign", "ctu_from_normal"),
        ("synthetic_benign_vs_ctu_background", "synthetic_benign", "ctu_background"),
        ("synthetic_beacon_vs_ctu_from_botnet", "synthetic_beacon", "ctu_from_botnet"),
    )
    rows: list[dict[str, Any]] = []
    for comparison_name, left_group, right_group in comparisons:
        for feature_name in DIAGNOSTIC_NUMERIC_FEATURES:
            left_values = _values_for_group(result.records, left_group, feature_name)
            right_values = _values_for_group(result.records, right_group, feature_name)
            if not left_values or not right_values:
                continue
            left_summary = _numeric_summary(left_values)
            right_summary = _numeric_summary(right_values)
            left_iqr = _iqr(left_values)
            right_iqr = _iqr(right_values)
            pooled_iqr = (left_iqr + right_iqr) / 2.0
            median_difference = abs(
                float(left_summary["median"]) - float(right_summary["median"])
            )
            fallback_scale = max(
                abs(float(left_summary["median"])),
                abs(float(right_summary["median"])),
                1.0,
            )
            scale = pooled_iqr if pooled_iqr > 0 else fallback_scale
            rows.append(
                {
                    "comparison": comparison_name,
                    "feature_name": feature_name,
                    "left_group": left_group,
                    "right_group": right_group,
                    "left_count": left_summary["count"],
                    "right_count": right_summary["count"],
                    "left_median": left_summary["median"],
                    "right_median": right_summary["median"],
                    "left_mean": left_summary["mean"],
                    "right_mean": right_summary["mean"],
                    "median_absolute_difference": median_difference,
                    "pooled_iqr": pooled_iqr,
                    "normalized_median_shift": median_difference / scale,
                }
            )
    rows.sort(
        key=lambda row: (row["comparison"], -float(row["normalized_median_shift"]))
    )
    _write_csv(path, rows)
    return path


def _write_protocol_port_summary(result: Ctu13FeatureDiagnosticResult) -> Path:
    path = result.output_dir / "ctu_protocol_port_summary.csv"
    rows: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str, str, str, int, str], int] = {}
    group_totals: dict[tuple[str, str, str], int] = {}
    for record in result.records:
        row = record.feature_row
        scenario = record.ctu_scenario or "synthetic"
        total_key = (record.group_name, record.source_family, scenario)
        group_totals[total_key] = group_totals.get(total_key, 0) + 1
        key = (
            record.group_name,
            record.source_family,
            scenario,
            row.flow_key.protocol,
            row.flow_key.dst_port,
            _port_bucket(row.flow_key.dst_port),
        )
        grouped[key] = grouped.get(key, 0) + 1

    for key, count in sorted(grouped.items(), key=lambda item: item[1], reverse=True):
        group_name, source_family, scenario, protocol, dst_port, port_bucket = key
        denominator = group_totals[(group_name, source_family, scenario)]
        rows.append(
            {
                "group_name": group_name,
                "source_family": source_family,
                "ctu_scenario": scenario,
                "protocol": protocol,
                "dst_port": dst_port,
                "dst_port_bucket": port_bucket,
                "flow_count": count,
                "group_share": count / denominator if denominator else 0.0,
            }
        )
    _write_csv(path, rows)
    return path


def _write_metadata(result: Ctu13FeatureDiagnosticResult) -> Path:
    path = result.output_dir / "ctu_diagnostic_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Synthetic vs CTU-13 feature-distribution diagnostic.",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "ctu_scenarios": [
            {
                "scenario_name": scenario.scenario_name,
                "input_path": str(scenario.input_path),
                "max_rows": scenario.max_rows,
            }
            for scenario in result.scenarios
        ],
        "synthetic_seeds": list(result.synthetic_seeds),
        "numeric_features": list(DIAGNOSTIC_NUMERIC_FEATURES),
        "group_counts": {
            group_name: sum(1 for record in result.records if record.group_name == group_name)
            for group_name in _group_names(result.records)
        },
        "notes": [
            "This diagnostic does not rerun detectors or change detector logic.",
            (
                "CTU Background is included only to compare feature distributions "
                "and diagnose false positives."
            ),
            (
                "Shift scores are simple normalized median differences, not formal hypothesis "
                "tests."
            ),
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _scenario_slices(
    records: list[DiagnosticFeatureRecord],
) -> list[tuple[str, list[DiagnosticFeatureRecord]]]:
    pooled_name = "pooled"
    slices = [(pooled_name, records)]
    scenarios = sorted({record.ctu_scenario for record in records if record.ctu_scenario})
    for scenario in scenarios:
        slices.append((scenario, [record for record in records if record.ctu_scenario == scenario]))
    return slices


def _group_names(
    records: tuple[DiagnosticFeatureRecord, ...] | list[DiagnosticFeatureRecord],
) -> list[str]:
    preferred_order = [
        "synthetic_benign",
        "synthetic_beacon",
        "ctu_from_normal",
        "ctu_background",
        "ctu_from_botnet",
    ]
    available = {record.group_name for record in records}
    return [group_name for group_name in preferred_order if group_name in available]


def _values_for_group(
    records: tuple[DiagnosticFeatureRecord, ...],
    group_name: str,
    feature_name: str,
) -> list[float]:
    return [
        value
        for record in records
        if record.group_name == group_name
        for value in [_feature_value(record.feature_row, feature_name)]
        if value is not None
    ]


def _feature_value(row: FlowFeatures, feature_name: str) -> float | None:
    value = getattr(row, feature_name)
    if value is None:
        return None
    return float(value)


def _numeric_summary(values: list[float | None]) -> dict[str, Any]:
    present = sorted(float(value) for value in values if value is not None)
    missing_count = len(values) - len(present)
    if not present:
        return {
            "count": 0,
            "missing_count": missing_count,
            "mean": None,
            "median": None,
            "std": None,
            "min": None,
            "p10": None,
            "p25": None,
            "p75": None,
            "p90": None,
            "max": None,
        }

    return {
        "count": len(present),
        "missing_count": missing_count,
        "mean": sum(present) / len(present),
        "median": float(median(present)),
        "std": _std(present),
        "min": present[0],
        "p10": _quantile(present, 0.10),
        "p25": _quantile(present, 0.25),
        "p75": _quantile(present, 0.75),
        "p90": _quantile(present, 0.90),
        "max": present[-1],
    }


def _iqr(values: list[float]) -> float:
    ordered = sorted(values)
    if len(ordered) < 2:
        return 0.0
    return _quantile(ordered, 0.75) - _quantile(ordered, 0.25)


def _quantile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + ((values[upper] - values[lower]) * fraction)


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean_value = sum(values) / len(values)
    return (sum((value - mean_value) ** 2 for value in values) / len(values)) ** 0.5


def _port_bucket(dst_port: int) -> str:
    named_ports = {
        53: "dns_53",
        80: "http_80",
        123: "ntp_123",
        443: "https_443",
        993: "imaps_993",
        13363: "ctu_common_13363",
        19083: "ctu_common_19083",
    }
    if dst_port in named_ports:
        return named_ports[dst_port]
    if dst_port < 1024:
        return "other_well_known_0_1023"
    if dst_port < 49152:
        return "registered_1024_49151"
    return "ephemeral_49152_plus"


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
    diagnostic = run_ctu13_feature_diagnostic()
    for written_path in export_ctu13_feature_diagnostic_tables(diagnostic):
        print(written_path)
