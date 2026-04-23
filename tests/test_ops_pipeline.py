from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from beacon_detector.ops import run_batch_score, run_rules_only_score, train_random_forest_model
from beacon_detector.ops.ingest import load_zeek_conn_log
from beacon_detector.ops.schema import validate_normalized_csv


class OperationalPipelineTests(unittest.TestCase):
    def test_validates_normalized_csv_required_columns(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_validate")
        path = output_dir / "bad.csv"
        path.write_text("timestamp,src_ip\n2026-01-01T00:00:00+00:00,10.0.0.5\n")

        result = validate_normalized_csv(path)

        self.assertFalse(result.is_valid)
        self.assertIn("dst_ip", {issue.column for issue in result.issues})

    def test_normalized_csv_rules_score_writes_default_outputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_score")
        input_path = output_dir / "normalized.csv"
        _write_periodic_normalized_csv(input_path)

        outputs = run_rules_only_score(
            input_path=input_path,
            input_format="normalized-csv",
            output_dir=output_dir / "out",
        )

        self.assertTrue(outputs.alerts_csv.exists())
        self.assertTrue(outputs.scored_flows_csv.exists())
        self.assertTrue(outputs.run_summary_json.exists())
        self.assertTrue(outputs.report_md.exists())

        alerts = _rows(outputs.alerts_csv)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["src_ip"], "10.0.0.5")
        self.assertEqual(alerts[0]["dst_ip"], "203.0.113.10")
        self.assertEqual(alerts[0]["src_ports_seen"], "1111;2222;3333;4444;5555")

        summary = json.loads(outputs.run_summary_json.read_text(encoding="utf-8"))
        self.assertEqual(summary["mode"], "rules_only")
        self.assertEqual(summary["src_port_policy"], "captured_but_not_grouped")
        self.assertEqual(summary["alert_count"], 1)

    def test_zeek_conn_log_adapter_loads_operational_events(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_zeek")
        path = output_dir / "conn.log"
        _write_zeek_conn_log(path)

        events = load_zeek_conn_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].src_ip, "10.0.0.5")
        self.assertEqual(events[0].dst_port, 443)
        self.assertEqual(events[0].protocol, "tcp")
        self.assertEqual(events[0].total_bytes, 150)

    def test_cli_score_writes_outputs(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_cli")
        input_path = output_dir / "normalized.csv"
        _write_periodic_normalized_csv(input_path)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "beacon_detector.cli.ops",
                "score",
                "--input",
                str(input_path),
                "--input-format",
                "normalized-csv",
                "--output-dir",
                str(output_dir / "out"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Operational scoring complete", completed.stdout)
        self.assertTrue((output_dir / "out" / "alerts.csv").exists())

    def test_cli_train_model_writes_artifact(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_cli_train")
        train_path = output_dir / "train.csv"
        _write_labelled_training_csv(train_path)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "beacon_detector.cli.ops",
                "train-model",
                "--train",
                str(train_path),
                "--output-dir",
                str(output_dir / "model"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Operational model training complete", completed.stdout)
        self.assertTrue((output_dir / "model" / "model.pkl").exists())
        self.assertTrue((output_dir / "model" / "metadata.json").exists())

    def test_train_model_and_score_with_saved_artifact(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_model")
        train_path = output_dir / "train.csv"
        score_path = output_dir / "score.csv"
        _write_labelled_training_csv(train_path)
        _write_periodic_normalized_csv(score_path)

        training_outputs = train_random_forest_model(
            train_paths=[train_path],
            output_dir=output_dir / "model",
        )

        self.assertTrue(training_outputs.model_file.exists())
        self.assertTrue(training_outputs.metadata_json.exists())
        metadata = json.loads(training_outputs.metadata_json.read_text(encoding="utf-8"))
        self.assertEqual(metadata["input_contract"], "normalized_csv_with_label")
        self.assertEqual(metadata["skipped_unknown_event_count"], 1)

        outputs = run_batch_score(
            input_path=score_path,
            input_format="normalized-csv",
            output_dir=output_dir / "out",
            model_artifact_path=training_outputs.model_dir,
        )

        summary = json.loads(outputs.run_summary_json.read_text(encoding="utf-8"))
        self.assertEqual(summary["mode"], "rules_random_forest_hybrid")
        self.assertEqual(summary["model_detector_name"], "random_forest_v1")
        scored_rows = _rows(outputs.scored_flows_csv)
        self.assertEqual(scored_rows[0]["detector_mode"], "rules_random_forest_hybrid")
        self.assertNotEqual(scored_rows[0]["rf_score"], "")


def _write_periodic_normalized_csv(path: Path) -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    for index, src_port in enumerate(("1111", "2222", "3333", "4444", "5555")):
        rows.append(
            {
                "timestamp": (start + timedelta(seconds=60 * index)).isoformat(),
                "src_ip": "10.0.0.5",
                "src_port": src_port,
                "direction": "->",
                "dst_ip": "203.0.113.10",
                "dst_port": "443",
                "protocol": "tcp",
                "total_bytes": "128",
                "duration_seconds": "1.0",
                "total_packets": "2",
            }
        )
    _write_csv(path, rows)


def _write_labelled_training_csv(path: Path) -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows: list[dict[str, str]] = []
    rows.extend(
        _training_flow_rows(
            start=start,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.10",
            dst_port="443",
            label="beacon",
            gaps=(0, 60, 120, 180, 240),
            sizes=(128, 128, 128, 128, 128),
        )
    )
    rows.extend(
        _training_flow_rows(
            start=start,
            src_ip="10.0.0.6",
            dst_ip="203.0.113.11",
            dst_port="443",
            label="beacon",
            gaps=(0, 75, 150, 225, 300),
            sizes=(96, 96, 96, 96, 96),
        )
    )
    rows.extend(
        _training_flow_rows(
            start=start,
            src_ip="10.0.0.50",
            dst_ip="198.51.100.20",
            dst_port="443",
            label="benign",
            gaps=(0, 7, 43, 210, 211),
            sizes=(400, 900, 120, 1800, 260),
        )
    )
    rows.extend(
        _training_flow_rows(
            start=start,
            src_ip="10.0.0.51",
            dst_ip="198.51.100.21",
            dst_port="53",
            label="benign",
            gaps=(0, 3, 19, 47, 180),
            sizes=(60, 120, 80, 240, 90),
        )
    )
    rows.append(
        {
            "timestamp": start.isoformat(),
            "src_ip": "10.0.0.99",
            "src_port": "9999",
            "direction": "->",
            "dst_ip": "192.0.2.99",
            "dst_port": "443",
            "protocol": "tcp",
            "total_bytes": "42",
            "duration_seconds": "1.0",
            "total_packets": "1",
            "label": "unknown",
        }
    )
    _write_csv(path, rows)


def _training_flow_rows(
    *,
    start: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: str,
    label: str,
    gaps: tuple[int, ...],
    sizes: tuple[int, ...],
) -> list[dict[str, str]]:
    rows = []
    for index, (gap, size) in enumerate(zip(gaps, sizes, strict=True)):
        rows.append(
            {
                "timestamp": (start + timedelta(seconds=gap)).isoformat(),
                "src_ip": src_ip,
                "src_port": str(4000 + index),
                "direction": "->",
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": "tcp",
                "total_bytes": str(size),
                "duration_seconds": "1.0",
                "total_packets": "2",
                "label": label,
            }
        )
    return rows


def _write_zeek_conn_log(path: Path) -> None:
    lines = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts",
        "1767225600.000000\tC1\t10.0.0.5\t1111\t203.0.113.10\t443\ttcp\t1.0\t100\t50\t2\t1",
        "1767225660.000000\tC2\t10.0.0.5\t2222\t203.0.113.10\t443\ttcp\t1.0\t100\t50\t2\t1",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as input_file:
        return list(csv.DictReader(input_file))


def _clean_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.rglob("*"):
        if child.is_file():
            child.unlink()
    return output_dir


if __name__ == "__main__":
    unittest.main()
