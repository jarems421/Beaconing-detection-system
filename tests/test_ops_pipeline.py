from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from beacon_detector.ops import run_rules_only_score
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
