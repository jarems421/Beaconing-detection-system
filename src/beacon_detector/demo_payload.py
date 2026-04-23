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
REPO_ROOT = Path(__file__).resolve().parents[2]


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
    display_input = source_filename or _display_path(scenario.input_path)
    display_model_dir = "models/operational/demo_rf"

    return {
        "scenario": {
            "id": scenario.id,
            "label": scenario.label,
            "description": scenario.description,
            "category": scenario.category,
            "input_format": scenario.input_format,
            "input_path": display_input,
            "input_name": Path(display_input).name,
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
                "description": (
                    "The flows the system thinks deserve review first, "
                    "with short reasons."
                ),
            },
            {
                "name": "scored_flows.csv",
                "description": (
                    "Every grouped flow with the rule score, model score, "
                    "and final combined score."
                ),
            },
            {
                "name": "run_summary.json",
                "description": (
                    "A machine-readable summary of what was loaded, what was "
                    "skipped, and which settings were used."
                ),
            },
            {
                "name": "report.md",
                "description": (
                    "A human-readable report that explains the run in plain "
                    "language and keeps the score wording conservative."
                ),
            },
        ],
        "previews": {
            "report_md": _sanitize_preview_text(
                score.report_md.read_text(encoding="utf-8"),
                actual_input_path=scenario.input_path,
                display_input_path=display_input,
                actual_model_path=training.model_dir,
                display_model_path=display_model_dir,
            ),
            "run_summary_json": json.dumps(_summary_preview(summary), indent=2),
            "alerts_csv": score.alerts_csv.read_text(encoding="utf-8"),
            "scored_flows_csv": score.scored_flows_csv.read_text(encoding="utf-8"),
            "training_report_md": _sanitize_preview_text(
                training.training_report_md.read_text(encoding="utf-8"),
                actual_input_path=DEMO_TRAIN_FALLBACK_PATH,
                display_input_path="data/operational/example_train.csv",
                actual_model_path=training.model_dir,
                display_model_path=display_model_dir,
            ),
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


DEMO_TRAIN_FALLBACK_PATH = REPO_ROOT / "data" / "operational" / "example_train.csv"


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def _sanitize_preview_text(
    text: str,
    *,
    actual_input_path: Path,
    display_input_path: str,
    actual_model_path: Path,
    display_model_path: str,
) -> str:
    replacements = {
        str(actual_input_path): display_input_path,
        actual_input_path.as_posix(): display_input_path,
        str(actual_model_path): display_model_path,
        actual_model_path.as_posix(): display_model_path,
    }
    cleaned = text
    for source, target in replacements.items():
        cleaned = cleaned.replace(source, target)
    return cleaned
