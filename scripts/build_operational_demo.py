from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from beacon_detector.ops import run_batch_score, train_random_forest_model

ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "data" / "operational" / "example_train.csv"
INPUT_PATH = ROOT / "data" / "operational" / "fixtures" / "netflow_demo.csv"
OUTPUT_PATH = ROOT / "docs" / "operational_demo_data.js"


def main() -> None:
    with TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        training = train_random_forest_model(
            train_paths=[TRAIN_PATH],
            output_dir=temp_root / "model",
        )
        score = run_batch_score(
            input_path=INPUT_PATH,
            input_format="netflow-ipfix-csv",
            output_dir=temp_root / "run",
            model_artifact_path=training.model_dir,
            threshold_profile="balanced",
        )

        summary = json.loads(score.run_summary_json.read_text(encoding="utf-8"))
        training_summary = json.loads(
            training.training_summary_json.read_text(encoding="utf-8")
        )
        alerts = _rows(score.alerts_csv)
        scored_flows = _rows(score.scored_flows_csv)
        bundle = {
            "title": "Operational Beaconing Demo",
            "subtitle": (
                "Checked-in NetFlow fixture scored through the operational hybrid "
                "workflow with skip diagnostics and conservative score wording."
            ),
            "commands": [
                (
                    "beacon-ops train-model --train "
                    "data/operational/example_train.csv "
                    "--output-dir models/operational/demo_rf"
                ),
                (
                    "beacon-ops score --input "
                    "data/operational/fixtures/netflow_demo.csv "
                    "--input-format netflow-ipfix-csv "
                    "--model-artifact models/operational/demo_rf "
                    "--profile balanced "
                    "--output-dir results/operational/demo"
                ),
            ],
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
            "alerts": [_alert_card(row) for row in alerts],
            "selected_alert_id": alerts[0]["rank"] if alerts else None,
            "scored_flows": [_scored_flow_card(row) for row in scored_flows],
            "skip_reasons": [
                {"reason": reason, "count": count}
                for reason, count in sorted(
                    summary["ingestion"]["skipped_row_reasons"].items()
                )
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
                    "description": (
                        "Analyst-readable report with conservative score "
                        "interpretation."
                    ),
                },
            ],
            "previews": {
                "report_md": score.report_md.read_text(encoding="utf-8"),
                "run_summary_json": json.dumps(_summary_preview(summary), indent=2),
                "alerts_csv": score.alerts_csv.read_text(encoding="utf-8"),
                "scored_flows_csv": score.scored_flows_csv.read_text(encoding="utf-8"),
                "training_report_md": training.training_report_md.read_text(
                    encoding="utf-8"
                ),
            },
            "calibration": {
                "status": training_summary["calibration"]["probability_calibration"],
                "brier_score": training_summary["calibration"]["brier_score"],
                "recommendation": training_summary["calibration"]["recommendation"],
            },
            "figures": [
                {
                    "path": "../results/figures/final_story/01_synthetic_detector_comparison.png",
                    "title": "Controlled Synthetic Benchmark",
                },
                {
                    "path": "../results/figures/final_story/02_minimum_evidence_core_result.png",
                    "title": "Minimum-Evidence Result",
                },
                {
                    "path": "../results/figures/final_story/03_ctu_three_stage_comparison.png",
                    "title": "CTU-13 Transfer Story",
                },
            ],
        }

    OUTPUT_PATH.write_text(
        "window.OPERATIONAL_DEMO_DATA = " + json.dumps(bundle, indent=2) + ";\n",
        encoding="utf-8",
    )
    print(OUTPUT_PATH)


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as input_file:
        return list(csv.DictReader(input_file))


def _alert_card(row: dict[str, str]) -> dict[str, object]:
    reasons = [reason.strip() for reason in row["top_reasons"].split("|") if reason.strip()]
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
    }


def _scored_flow_card(row: dict[str, str]) -> dict[str, object]:
    return {
        "flow": (
            f"{row['src_ip']} -> {row['dst_ip']}:{row['dst_port']}/{row['protocol']}"
        ),
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


if __name__ == "__main__":
    main()
