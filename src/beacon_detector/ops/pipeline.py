from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.data.types import TrafficEvent
from beacon_detector.detection.rules import (
    FROZEN_RULE_BASELINE_NAME,
    HIGH_PRECISION_RULE_BASELINE_THRESHOLDS,
    RuleDetectionResult,
    RuleThresholds,
    detect_flow_feature_rows,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import Flow, FlowKey, build_flows

from .ingest import OperationalInputFormat, load_operational_events
from .schema import OperationalEvent

ALERT_COLUMNS = [
    "rank",
    "severity",
    "confidence",
    "score",
    "threshold",
    "src_ip",
    "direction",
    "dst_ip",
    "dst_port",
    "protocol",
    "first_seen",
    "last_seen",
    "event_count",
    "total_bytes",
    "src_ports_seen",
    "top_reasons",
]
SCORED_COLUMNS = [
    "predicted_label",
    "score",
    "threshold",
    "src_ip",
    "direction",
    "dst_ip",
    "dst_port",
    "protocol",
    "first_seen",
    "last_seen",
    "event_count",
    "total_bytes",
    "mean_interarrival_seconds",
    "inter_arrival_cv",
    "periodicity_score",
    "size_cv",
    "src_ports_seen",
    "triggered_rules",
]


@dataclass(frozen=True, slots=True)
class OpsScoreOutputs:
    alerts_csv: Path
    scored_flows_csv: Path
    run_summary_json: Path
    report_md: Path


@dataclass(frozen=True, slots=True)
class OpsFlowContext:
    source_ports_by_key: dict[FlowKey, tuple[str, ...]]


def run_rules_only_score(
    *,
    input_path: str | Path,
    input_format: OperationalInputFormat,
    output_dir: str | Path,
    thresholds: RuleThresholds | None = None,
) -> OpsScoreOutputs:
    thresholds = thresholds or HIGH_PRECISION_RULE_BASELINE_THRESHOLDS
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    events = load_operational_events(input_path, input_format=input_format)
    flows, context = build_operational_flows(events)
    feature_rows = extract_features_from_flows(flows)
    results = detect_flow_feature_rows(feature_rows, thresholds=thresholds)

    feature_by_key = {row.flow_key: row for row in feature_rows}
    flow_by_key = {flow.flow_key: flow for flow in flows}
    scored_rows = [
        _scored_row(
            result,
            features=feature_by_key[result.flow_key],
            flow=flow_by_key[result.flow_key],
            context=context,
        )
        for result in results
    ]
    alert_rows = _alert_rows(
        results,
        feature_by_key=feature_by_key,
        flow_by_key=flow_by_key,
        context=context,
    )

    alerts_csv = output_path / "alerts.csv"
    scored_flows_csv = output_path / "scored_flows.csv"
    run_summary_json = output_path / "run_summary.json"
    report_md = output_path / "report.md"

    _write_csv(alerts_csv, alert_rows, fieldnames=ALERT_COLUMNS)
    _write_csv(scored_flows_csv, scored_rows, fieldnames=SCORED_COLUMNS)
    summary = _run_summary(
        input_path=Path(input_path),
        input_format=input_format,
        thresholds=thresholds,
        event_count=len(events),
        flow_count=len(flows),
        alert_count=len(alert_rows),
    )
    run_summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    report_md.write_text(
        _report_markdown(summary=summary, alert_rows=alert_rows),
        encoding="utf-8",
    )

    return OpsScoreOutputs(
        alerts_csv=alerts_csv,
        scored_flows_csv=scored_flows_csv,
        run_summary_json=run_summary_json,
        report_md=report_md,
    )


def build_operational_flows(
    events: list[OperationalEvent],
) -> tuple[list[Flow], OpsFlowContext]:
    source_ports_by_key: dict[FlowKey, set[str]] = {}
    traffic_events: list[TrafficEvent] = []
    for event in events:
        key = FlowKey(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            protocol=event.protocol,
            direction=event.direction,
            src_port=None,
        )
        if event.src_port:
            source_ports_by_key.setdefault(key, set()).add(event.src_port)
        traffic_events.append(
            TrafficEvent(
                timestamp=event.timestamp,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                protocol=event.protocol,
                size_bytes=event.total_bytes,
                label="benign",
                scenario_name="operational",
                src_port=None,
                direction=event.direction,
            )
        )

    context = OpsFlowContext(
        source_ports_by_key={
            key: tuple(sorted(source_ports))
            for key, source_ports in source_ports_by_key.items()
        }
    )
    return build_flows(traffic_events), context


def _alert_rows(
    results: list[RuleDetectionResult],
    *,
    feature_by_key: dict[FlowKey, FlowFeatures],
    flow_by_key: dict[FlowKey, Flow],
    context: OpsFlowContext,
) -> list[dict[str, Any]]:
    alert_results = sorted(
        [result for result in results if result.predicted_label == "beacon"],
        key=lambda result: result.score,
        reverse=True,
    )
    return [
        {
            "rank": rank,
            "severity": _severity(result),
            "confidence": _confidence(result),
            **_flow_identity_row(
                result,
                features=feature_by_key[result.flow_key],
                flow=flow_by_key[result.flow_key],
                context=context,
            ),
            "top_reasons": " | ".join(result.triggered_reasons),
        }
        for rank, result in enumerate(alert_results, start=1)
    ]


def _scored_row(
    result: RuleDetectionResult,
    *,
    features: FlowFeatures,
    flow: Flow,
    context: OpsFlowContext,
) -> dict[str, Any]:
    return {
        "predicted_label": result.predicted_label,
        **_flow_identity_row(result, features=features, flow=flow, context=context),
        "mean_interarrival_seconds": features.mean_interarrival_seconds,
        "inter_arrival_cv": features.inter_arrival_cv,
        "periodicity_score": features.periodicity_score,
        "size_cv": features.size_cv,
        "triggered_rules": " | ".join(
            contribution.rule_name
            for contribution in result.contributions
            if contribution.fired and contribution.score > 0
        ),
    }


def _flow_identity_row(
    result: RuleDetectionResult,
    *,
    features: FlowFeatures,
    flow: Flow,
    context: OpsFlowContext,
) -> dict[str, Any]:
    key = result.flow_key
    return {
        "score": result.score,
        "threshold": result.threshold,
        "src_ip": key.src_ip,
        "direction": key.direction or "",
        "dst_ip": key.dst_ip,
        "dst_port": key.dst_port,
        "protocol": key.protocol,
        "first_seen": flow.start_time.isoformat(),
        "last_seen": flow.end_time.isoformat(),
        "event_count": features.event_count,
        "total_bytes": features.total_bytes,
        "src_ports_seen": ";".join(context.source_ports_by_key.get(key, ())),
    }


def _run_summary(
    *,
    input_path: Path,
    input_format: str,
    thresholds: RuleThresholds,
    event_count: int,
    flow_count: int,
    alert_count: int,
) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_path": str(input_path),
        "input_format": input_format,
        "mode": "rules_only",
        "detector_name": FROZEN_RULE_BASELINE_NAME,
        "alert_profile": "conservative",
        "prediction_threshold": thresholds.prediction_threshold,
        "flow_grouping_key": [
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "direction",
        ],
        "src_port_policy": "captured_but_not_grouped",
        "time_windowing": "whole_file_batch",
        "input_event_count": event_count,
        "scored_flow_count": flow_count,
        "alert_count": alert_count,
        "outputs": [
            "alerts.csv",
            "scored_flows.csv",
            "run_summary.json",
            "report.md",
        ],
    }


def _report_markdown(
    *,
    summary: dict[str, Any],
    alert_rows: list[dict[str, Any]],
) -> str:
    lines = [
        "# Beaconing Batch Report",
        "",
        f"- Input: `{summary['input_path']}`",
        f"- Input format: `{summary['input_format']}`",
        f"- Detector: `{summary['detector_name']}`",
        f"- Alert profile: `{summary['alert_profile']}`",
        f"- Input events: {summary['input_event_count']}",
        f"- Scored flows: {summary['scored_flow_count']}",
        f"- Alerts: {summary['alert_count']}",
        "",
        "## Top Alerts",
        "",
    ]
    if not alert_rows:
        lines.extend(["No beaconing alerts exceeded the conservative threshold.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Rank | Severity | Score | Flow | Events | Reasons |",
            "| --- | --- | ---: | --- | ---: | --- |",
        ]
    )
    for row in alert_rows[:10]:
        flow = (
            f"{row['src_ip']} {row['direction']} "
            f"{row['dst_ip']}:{row['dst_port']}/{row['protocol']}"
        )
        lines.append(
            "| {rank} | {severity} | {score:.3f} | `{flow}` | {event_count} | {reasons} |".format(
                rank=row["rank"],
                severity=row["severity"],
                score=float(row["score"]),
                flow=flow,
                event_count=row["event_count"],
                reasons=row["top_reasons"] or "",
            )
        )
    lines.append("")
    return "\n".join(lines)


def _severity(result: RuleDetectionResult) -> str:
    margin = result.score - result.threshold
    if margin >= 2.0:
        return "critical"
    if margin >= 1.0:
        return "high"
    return "medium"


def _confidence(result: RuleDetectionResult) -> float:
    if result.threshold <= 0:
        return 1.0
    return min(result.score / result.threshold, 1.0)


def _write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
