from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection.rules import (
    FROZEN_RULE_BASELINE_NAME,
    HIGH_PRECISION_RULE_BASELINE_THRESHOLDS,
    RuleDetectionResult,
    RuleThresholds,
    detect_flow_feature_rows,
)
from beacon_detector.detection.supervised import (
    SupervisedDetectionResult,
    detect_flow_feature_rows_supervised,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import Flow, FlowKey

from .grouping import OpsFlowContext, build_operational_flows
from .ingest import (
    OperationalIngestDiagnostics,
    OperationalInputFormat,
    load_operational_input,
)
from .model import (
    OpsModelArtifact,
    ThresholdProfileName,
    load_ops_model_artifact,
    model_with_threshold_profile,
    runtime_environment,
)

ALERT_COLUMNS = [
    "rank",
    "severity",
    "confidence",
    "detector_mode",
    "score",
    "threshold",
    "hybrid_score",
    "rule_score",
    "rf_score",
    "rf_threshold",
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
    "top_model_features",
]
SCORED_COLUMNS = [
    "predicted_label",
    "detector_mode",
    "score",
    "threshold",
    "hybrid_score",
    "rule_predicted_label",
    "rule_score",
    "rule_threshold",
    "rf_predicted_label",
    "rf_score",
    "rf_threshold",
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
    "top_model_features",
]


@dataclass(frozen=True, slots=True)
class OpsScoreOutputs:
    alerts_csv: Path
    scored_flows_csv: Path
    run_summary_json: Path
    report_md: Path


def run_rules_only_score(
    *,
    input_path: str | Path,
    input_format: OperationalInputFormat,
    output_dir: str | Path,
    thresholds: RuleThresholds | None = None,
    threshold_profile: ThresholdProfileName = "conservative",
) -> OpsScoreOutputs:
    return run_batch_score(
        input_path=input_path,
        input_format=input_format,
        output_dir=output_dir,
        thresholds=thresholds,
        threshold_profile=threshold_profile,
    )


def run_batch_score(
    *,
    input_path: str | Path,
    input_format: OperationalInputFormat,
    output_dir: str | Path,
    thresholds: RuleThresholds | None = None,
    model_artifact_path: str | Path | None = None,
    threshold_profile: ThresholdProfileName = "conservative",
) -> OpsScoreOutputs:
    thresholds = thresholds or HIGH_PRECISION_RULE_BASELINE_THRESHOLDS
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    load_result = load_operational_input(input_path, input_format=input_format)
    events = load_result.events
    if not events:
        raise ValueError(
            _no_loaded_events_message(
                input_path=Path(input_path),
                diagnostics=load_result.diagnostics,
            )
        )
    flows, context = build_operational_flows(events)
    feature_rows = extract_features_from_flows(flows)
    rule_results = detect_flow_feature_rows(feature_rows, thresholds=thresholds)
    model_artifact = (
        load_ops_model_artifact(model_artifact_path)
        if model_artifact_path is not None
        else None
    )
    supervised_results = (
        detect_flow_feature_rows_supervised(
            feature_rows,
            model=model_with_threshold_profile(model_artifact, threshold_profile),
        )
        if model_artifact is not None
        else []
    )
    supervised_by_key = {result.flow_key: result for result in supervised_results}

    feature_by_key = {row.flow_key: row for row in feature_rows}
    flow_by_key = {flow.flow_key: flow for flow in flows}
    scored_rows = [
        _scored_row(
            rule_result,
            supervised_result=supervised_by_key.get(rule_result.flow_key),
            features=feature_by_key[rule_result.flow_key],
            flow=flow_by_key[rule_result.flow_key],
            context=context,
        )
        for rule_result in rule_results
    ]
    alert_rows = _alert_rows(
        rule_results,
        supervised_by_key=supervised_by_key,
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
        model_artifact=model_artifact,
        model_artifact_path=Path(model_artifact_path) if model_artifact_path else None,
        threshold_profile=threshold_profile,
        event_count=len(events),
        flow_count=len(flows),
        alert_count=len(alert_rows),
        ingestion=load_result.diagnostics,
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


def _alert_rows(
    results: list[RuleDetectionResult],
    *,
    supervised_by_key: dict[FlowKey, SupervisedDetectionResult],
    feature_by_key: dict[FlowKey, FlowFeatures],
    flow_by_key: dict[FlowKey, Flow],
    context: OpsFlowContext,
) -> list[dict[str, Any]]:
    alert_results = sorted(
        [
            result
            for result in results
            if _final_predicted_label(result, supervised_by_key.get(result.flow_key))
            == "beacon"
        ],
        key=lambda result: _final_score(result, supervised_by_key.get(result.flow_key)),
        reverse=True,
    )
    return [
        {
            "rank": rank,
            "severity": _severity(
                _final_score(result, supervised_by_key.get(result.flow_key)),
                _final_threshold(result, supervised_by_key.get(result.flow_key)),
            ),
            "confidence": _confidence(
                _final_score(result, supervised_by_key.get(result.flow_key)),
                _final_threshold(result, supervised_by_key.get(result.flow_key)),
            ),
            "detector_mode": _detector_mode(supervised_by_key.get(result.flow_key)),
            **_flow_identity_row(
                result,
                supervised_result=supervised_by_key.get(result.flow_key),
                features=feature_by_key[result.flow_key],
                flow=flow_by_key[result.flow_key],
                context=context,
            ),
            "top_reasons": _alert_reasons(
                result,
                supervised_by_key.get(result.flow_key),
            ),
            "top_model_features": _top_model_features(
                supervised_by_key.get(result.flow_key)
            ),
        }
        for rank, result in enumerate(alert_results, start=1)
    ]


def _scored_row(
    result: RuleDetectionResult,
    *,
    supervised_result: SupervisedDetectionResult | None,
    features: FlowFeatures,
    flow: Flow,
    context: OpsFlowContext,
) -> dict[str, Any]:
    return {
        "predicted_label": _final_predicted_label(result, supervised_result),
        "detector_mode": _detector_mode(supervised_result),
        **_flow_identity_row(
            result,
            supervised_result=supervised_result,
            features=features,
            flow=flow,
            context=context,
        ),
        "rule_predicted_label": result.predicted_label,
        "rule_score": result.score,
        "rule_threshold": result.threshold,
        "rf_predicted_label": (
            supervised_result.predicted_label if supervised_result is not None else ""
        ),
        "rf_score": supervised_result.score if supervised_result is not None else "",
        "rf_threshold": (
            supervised_result.threshold if supervised_result is not None else ""
        ),
        "mean_interarrival_seconds": features.mean_interarrival_seconds,
        "inter_arrival_cv": features.inter_arrival_cv,
        "periodicity_score": features.periodicity_score,
        "size_cv": features.size_cv,
        "triggered_rules": " | ".join(
            contribution.rule_name
            for contribution in result.contributions
            if contribution.fired and contribution.score > 0
        ),
        "top_model_features": _top_model_features(supervised_result),
    }


def _flow_identity_row(
    result: RuleDetectionResult,
    *,
    supervised_result: SupervisedDetectionResult | None,
    features: FlowFeatures,
    flow: Flow,
    context: OpsFlowContext,
) -> dict[str, Any]:
    key = result.flow_key
    return {
        "score": _final_score(result, supervised_result),
        "threshold": _final_threshold(result, supervised_result),
        "hybrid_score": _hybrid_score(result, supervised_result),
        "rule_score": result.score,
        "rf_score": supervised_result.score if supervised_result is not None else "",
        "rf_threshold": supervised_result.threshold if supervised_result is not None else "",
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
    model_artifact: OpsModelArtifact | None,
    model_artifact_path: Path | None,
    threshold_profile: ThresholdProfileName,
    event_count: int,
    flow_count: int,
    alert_count: int,
    ingestion: OperationalIngestDiagnostics,
) -> dict[str, Any]:
    detector_mode = (
        "rules_random_forest_hybrid" if model_artifact is not None else "rules_only"
    )
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_path": str(input_path),
        "input_format": input_format,
        "mode": detector_mode,
        "detector_name": FROZEN_RULE_BASELINE_NAME,
        "model_artifact_path": str(model_artifact_path) if model_artifact_path else None,
        "model_detector_name": (
            model_artifact.model.detector_name if model_artifact is not None else None
        ),
        "model_schema_version": (
            model_artifact.metadata.get("schema_version")
            if model_artifact is not None
            else None
        ),
        "model_metadata": _model_summary(model_artifact),
        "alert_profile": threshold_profile,
        "threshold_profile": _threshold_profile_summary(
            model_artifact,
            threshold_profile,
            thresholds,
        ),
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
        "ingestion": {
            "input_row_count": ingestion.input_row_count,
            "loaded_event_count": ingestion.loaded_event_count,
            "skipped_row_count": ingestion.skipped_row_count,
            "skipped_row_reasons": ingestion.skipped_row_reasons,
        },
        "scored_flow_count": flow_count,
        "alert_count": alert_count,
        "input_schema": {
            "contract": "normalized_csv",
            "required_columns": [
                "timestamp",
                "src_ip",
                "direction",
                "dst_ip",
                "dst_port",
                "protocol",
                "total_bytes",
            ],
            "optional_columns": [
                "src_port",
                "duration_seconds",
                "total_packets",
                "label",
            ],
        },
        "score_semantics": {
            "score": (
                "Rules score in rules-only mode. In hybrid mode, max(rule_ratio, "
                "rf_score_ratio)."
            ),
            "rule_score": "Interpretable rule score before threshold comparison.",
            "rf_score": (
                "Uncalibrated Random Forest beacon score when a model artifact is "
                "loaded. Use it for ranking and thresholding, not as a calibrated "
                "probability."
            ),
            "hybrid_score": "Normalized ranking score used for final hybrid ordering.",
            "confidence": (
                "Threshold-relative display heuristic for alert severity; not a "
                "calibrated probability."
            ),
        },
        "output_manifest": _output_manifest(),
        "runtime_environment": runtime_environment(),
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
        f"- Mode: `{summary['mode']}`",
        f"- Alert profile: `{summary['alert_profile']}`",
        f"- Grouping key: `{'+'.join(summary['flow_grouping_key'])}`",
        f"- Source port policy: `{summary['src_port_policy']}`",
        f"- Time windowing: `{summary['time_windowing']}`",
        f"- Input events: {summary['input_event_count']}",
        f"- Scored flows: {summary['scored_flow_count']}",
        f"- Alerts: {summary['alert_count']}",
        "",
        "## Ingestion",
        "",
        f"- Input rows: {summary['ingestion']['input_row_count']}",
        f"- Loaded events: {summary['ingestion']['loaded_event_count']}",
        f"- Skipped rows: {summary['ingestion']['skipped_row_count']}",
        f"- Skip reasons: {_skip_reason_text(summary['ingestion']['skipped_row_reasons'])}",
        "",
        "## Outputs",
        "",
        "| File | Role |",
        "| --- | --- |",
        *[
            f"| `{artifact['path']}` | {artifact['role']} |"
            for artifact in summary["output_manifest"]
        ],
        "",
        "## Model",
        "",
        *_model_report_lines(summary),
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


def _output_manifest() -> list[dict[str, Any]]:
    return [
        {
            "path": "alerts.csv",
            "role": "Ranked alert rows exceeding the active decision policy.",
            "columns": ALERT_COLUMNS,
        },
        {
            "path": "scored_flows.csv",
            "role": "All scored grouped flows with rules, RF, and hybrid score fields.",
            "columns": SCORED_COLUMNS,
        },
        {
            "path": "run_summary.json",
            "role": "Machine-readable run manifest, scoring policy, and environment.",
        },
        {
            "path": "report.md",
            "role": "Human-readable batch scoring report.",
        },
    ]


def _model_summary(model_artifact: OpsModelArtifact | None) -> dict[str, Any] | None:
    if model_artifact is None:
        return None
    metadata = model_artifact.metadata
    return {
        "detector_name": metadata.get("detector_name"),
        "schema_version": metadata.get("schema_version"),
        "feature_count": metadata.get("feature_count"),
        "feature_names": metadata.get("feature_names"),
        "label_mapping": metadata.get("label_mapping"),
        "training_data": metadata.get("training_data"),
        "validation": metadata.get("validation"),
        "calibration": metadata.get("calibration"),
        "runtime_environment": metadata.get("runtime_environment"),
        "persistence": metadata.get("persistence"),
        "threshold_profiles": metadata.get("threshold_profiles"),
    }


def _no_loaded_events_message(
    *,
    input_path: Path,
    diagnostics: OperationalIngestDiagnostics,
) -> str:
    return (
        f"No supported operational events were loaded from {input_path}. "
        f"Input rows={diagnostics.input_row_count}, "
        f"skipped_rows={diagnostics.skipped_row_count}, "
        f"skip_reasons={_skip_reason_text(diagnostics.skipped_row_reasons)}."
    )


def _model_report_lines(summary: dict[str, Any]) -> list[str]:
    model = summary.get("model_metadata")
    if model is None:
        return [
            "No model artifact was loaded. This run used the conservative rules path.",
        ]
    validation = model.get("validation") or {}
    metrics = validation.get("metrics") or {}
    calibration = model.get("calibration") or {}
    return [
        f"- Model artifact: `{summary['model_artifact_path']}`",
        f"- Model detector: `{model.get('detector_name')}`",
        f"- Feature count: {model.get('feature_count')}",
        f"- Active threshold profile: `{summary['alert_profile']}`",
        f"- Active RF threshold: {summary['threshold_profile']['threshold']:.3f}",
        f"- Validation strategy: `{validation.get('strategy')}`",
        f"- Validation folds: {validation.get('executed_folds')}",
        f"- Validation F1 mean: {float(metrics.get('mean_f1_score', 0.0)):.3f}",
        "- Validation false-positive-rate mean: "
        f"{float(metrics.get('mean_false_positive_rate', 0.0)):.3f}",
        "- Calibration status: "
        f"`{calibration.get('probability_calibration', 'not_reported')}`",
        "- Calibration Brier score: "
        f"{_format_optional_metric(calibration.get('brier_score'))}",
        "- RF scores are uncalibrated model scores. Use them for ranking and "
        "threshold policies, not as direct probabilities.",
    ]


def _threshold_profile_summary(
    model_artifact: OpsModelArtifact | None,
    profile: ThresholdProfileName,
    thresholds: RuleThresholds,
) -> dict[str, Any]:
    if model_artifact is None:
        return {
            "profile": "conservative",
            "threshold": thresholds.prediction_threshold,
            "source": "rules_baseline",
            "selection_method": "fixed_rule_threshold",
        }
    profiles = model_artifact.metadata.get("threshold_profiles") or {}
    profile_metadata = profiles.get(profile) or {}
    return {
        "profile": profile,
        "threshold": float(
            profile_metadata.get(
                "threshold",
                model_artifact.model.config.prediction_threshold,
            )
        ),
        "source": "model_artifact",
        "selection_method": profile_metadata.get(
            "selection_method",
            "saved_model_default",
        ),
        "optimized_metric": profile_metadata.get("optimized_metric"),
        "metrics": profile_metadata.get("metrics"),
    }


def _final_predicted_label(
    result: RuleDetectionResult,
    supervised_result: SupervisedDetectionResult | None,
) -> str:
    if supervised_result is not None and supervised_result.predicted_label == "beacon":
        return "beacon"
    return result.predicted_label


def _final_score(
    result: RuleDetectionResult,
    supervised_result: SupervisedDetectionResult | None,
) -> float:
    if supervised_result is None:
        return result.score
    return _hybrid_score(result, supervised_result)


def _final_threshold(
    result: RuleDetectionResult,
    supervised_result: SupervisedDetectionResult | None,
) -> float:
    return 1.0 if supervised_result is not None else result.threshold


def _hybrid_score(
    result: RuleDetectionResult,
    supervised_result: SupervisedDetectionResult | None,
) -> float:
    if supervised_result is None:
        return result.score
    rule_ratio = result.score / result.threshold if result.threshold > 0 else 0.0
    rf_ratio = (
        supervised_result.score / supervised_result.threshold
        if supervised_result.threshold > 0
        else 0.0
    )
    return max(rule_ratio, rf_ratio)


def _detector_mode(supervised_result: SupervisedDetectionResult | None) -> str:
    return "rules_random_forest_hybrid" if supervised_result is not None else "rules_only"


def _top_model_features(
    supervised_result: SupervisedDetectionResult | None,
) -> str:
    if supervised_result is None:
        return ""
    return " | ".join(supervised_result.top_model_features)


def _alert_reasons(
    result: RuleDetectionResult,
    supervised_result: SupervisedDetectionResult | None,
) -> str:
    reasons = list(result.triggered_reasons)
    if supervised_result is not None and supervised_result.predicted_label == "beacon":
        reasons.append(
            "random forest score "
            f"{supervised_result.score:.3f} >= {supervised_result.threshold:.3f}"
        )
    return " | ".join(reasons)


def _severity(score: float, threshold: float) -> str:
    margin = score - threshold
    if margin >= 2.0:
        return "critical"
    if margin >= 1.0:
        return "high"
    return "medium"


def _confidence(score: float, threshold: float) -> float:
    if threshold <= 0:
        return 1.0
    return min(score / threshold, 1.0)


def _skip_reason_text(skipped_row_reasons: dict[str, int]) -> str:
    if not skipped_row_reasons:
        return "none"
    return ", ".join(
        f"{reason}={count}"
        for reason, count in sorted(skipped_row_reasons.items())
    )


def _format_optional_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}"


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
