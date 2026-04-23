from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from beacon_detector.ops.ingest import OperationalInputFormat
from beacon_detector.ops.model import OpsModelTrainingResult, ThresholdProfileName
from beacon_detector.ops.pipeline import OpsScoreOutputs

PayloadSourceKind = Literal["sample", "uploaded"]


@dataclass(frozen=True, slots=True)
class DemoScenario:
    id: str
    label: str
    description: str
    input_path: Path
    input_format: OperationalInputFormat
    profile: ThresholdProfileName = "balanced"
    category: str = "sample"


def build_demo_payload(
    *,
    training: OpsModelTrainingResult,
    score: OpsScoreOutputs,
    scenario: DemoScenario,
    source_kind: PayloadSourceKind,
    source_label: str | None = None,
    source_filename: str | None = None,
) -> dict[str, object]:
    summary = json.loads(score.run_summary_json.read_text(encoding="utf-8"))
    training_summary = json.loads(training.training_summary_json.read_text(encoding="utf-8"))
    alerts = _rows(score.alerts_csv)
    scored_flows = _rows(score.scored_flows_csv)
    display_input = source_filename or scenario.input_path.as_posix()

    return {
        "scenario": {
            "id": scenario.id,
            "label": scenario.label,
            "description": scenario.description,
            "category": scenario.category,
            "input_format": scenario.input_format,
            "input_path": str(scenario.input_path),
            "input_name": scenario.input_path.name,
            "profile": scenario.profile,
        },
        "source": {
            "kind": source_kind,
            "label": source_label or scenario.label,
            "filename": source_filename,
        },
        "commands": {
            "train_model": (
                "beacon-ops train-model --train "
                "data/operational/example_train.csv "
                "--output-dir models/operational/demo_rf"
            ),
            "score": (
                f"beacon-ops score --input {display_input} "
                f"--input-format {scenario.input_format} "
                "--model-artifact models/operational/demo_rf "
                f"--profile {scenario.profile} "
                "--output-dir results/operational/demo"
            ),
        },
        "metrics": [
            {"label": "Input rows", "value": summary["ingestion"]["input_row_count"]},
            {
                "label": "Loaded events",
                "value": summary["ingestion"]["loaded_event_count"],
            },
            {
                "label": "Skipped rows",
                "value": summary["ingestion"]["skipped_row_count"],
            },
            {"label": "Alert count", "value": summary["alert_count"]},
            {"label": "Profile", "value": summary["alert_profile"]},
            {"label": "Mode", "value": summary["mode"]},
        ],
        "summary": _summary_preview(summary),
        "alerts": [_alert_card(row) for row in alerts],
        "selected_alert_id": alerts[0]["rank"] if alerts else None,
        "scored_flows": [_scored_flow_card(row) for row in scored_flows],
        "skip_reasons": [
            {"reason": reason, "count": count}
            for reason, count in sorted(summary["ingestion"]["skipped_row_reasons"].items())
        ],
        "output_files": [
            {
                "name": "alerts.csv",
                "description": "Ranked suspicious flows with reasons and scoring context.",
            },
            {
                "name": "scored_flows.csv",
                "description": "Rules, RF, and hybrid scores for every grouped flow.",
            },
            {
                "name": "run_summary.json",
                "description": "Machine-readable ingestion diagnostics and threshold metadata.",
            },
            {
                "name": "report.md",
                "description": "Analyst-readable report with conservative score interpretation.",
            },
        ],
        "previews": {
            "report_md": score.report_md.read_text(encoding="utf-8"),
            "run_summary_json": json.dumps(_summary_preview(summary), indent=2),
            "alerts_csv": score.alerts_csv.read_text(encoding="utf-8"),
            "scored_flows_csv": score.scored_flows_csv.read_text(encoding="utf-8"),
            "training_report_md": training.training_report_md.read_text(encoding="utf-8"),
        },
        "calibration": {
            "status": training_summary["calibration"]["probability_calibration"],
            "brier_score": training_summary["calibration"]["brier_score"],
            "recommendation": training_summary["calibration"]["recommendation"],
        },
        "score_semantics": summary["score_semantics"],
        "figures": [
            {
                "path": "/figures/01_synthetic_detector_comparison.png",
                "title": "Controlled Synthetic Benchmark",
            },
            {
                "path": "/figures/02_minimum_evidence_core_result.png",
                "title": "Minimum-Evidence Result",
            },
            {
                "path": "/figures/03_ctu_three_stage_comparison.png",
                "title": "CTU-13 Transfer Story",
            },
        ],
    }


def build_manifest_entry(payload: dict[str, object]) -> dict[str, object]:
    scenario = payload["scenario"]
    assert isinstance(scenario, dict)
    summary = payload["summary"]
    assert isinstance(summary, dict)
    return {
        "id": scenario["id"],
        "label": scenario["label"],
        "description": scenario["description"],
        "category": scenario["category"],
        "input_format": scenario["input_format"],
        "input_name": scenario["input_name"],
        "profile": scenario["profile"],
        "alert_count": summary["alert_count"],
        "loaded_events": summary["loaded_events"],
        "skipped_rows": summary["skipped_rows"],
        "payload_path": f"/demo-scenarios/{scenario['id']}.json",
    }


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as input_file:
        return list(csv.DictReader(input_file))


def _alert_card(row: dict[str, str]) -> dict[str, object]:
    reasons = [reason.strip() for reason in row["top_reasons"].split("|") if reason.strip()]
    model_features = [
        feature.strip()
        for feature in row["top_model_features"].split("|")
        if feature.strip()
    ]
    return {
        "id": row["rank"],
        "severity": row["severity"],
        "src": row["src_ip"],
        "dst": row["dst_ip"],
        "port": int(row["dst_port"]),
        "proto": row["protocol"],
        "mode": row["detector_mode"],
        "score": float(row["score"]),
        "hybrid_score": float(row["hybrid_score"]),
        "rf_score": float(row["rf_score"] or 0.0),
        "event_count": int(row["event_count"]),
        "bytes": int(row["total_bytes"]),
        "src_ports_seen": row["src_ports_seen"],
        "reasons": reasons,
        "features": row["top_model_features"],
        "model_features": model_features,
        "confidence": float(row["confidence"]),
        "threshold": float(row["threshold"]),
        "rf_threshold": float(row["rf_threshold"] or 0.0),
    }


def _scored_flow_card(row: dict[str, str]) -> dict[str, object]:
    return {
        "flow": f"{row['src_ip']} -> {row['dst_ip']}:{row['dst_port']}/{row['protocol']}",
        "rule_score": float(row["rule_score"]),
        "rf_score": float(row["rf_score"] or 0.0),
        "hybrid_score": float(row["hybrid_score"]),
        "predicted_label": row["predicted_label"],
        "evidence": row["triggered_rules"] or "no triggered rules",
    }


def _summary_preview(summary: dict[str, object]) -> dict[str, object]:
    threshold_profile = summary["threshold_profile"]
    assert isinstance(threshold_profile, dict)
    metrics = threshold_profile.get("metrics", {})
    return {
        "input_format": summary["input_format"],
        "mode": summary["mode"],
        "profile": summary["alert_profile"],
        "input_rows": summary["ingestion"]["input_row_count"],
        "loaded_events": summary["ingestion"]["loaded_event_count"],
        "skipped_rows": summary["ingestion"]["skipped_row_count"],
        "skip_reasons": summary["ingestion"]["skipped_row_reasons"],
        "alert_count": summary["alert_count"],
        "threshold": threshold_profile.get("threshold"),
        "selection_method": threshold_profile.get("selection_method"),
        "optimized_metric": threshold_profile.get("optimized_metric"),
        "tradeoff_summary": {
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1": metrics.get("f1_score"),
            "false_positive_rate": metrics.get("false_positive_rate"),
        },
        "score_semantics": summary["score_semantics"],
    }
