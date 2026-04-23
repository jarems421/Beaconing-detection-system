from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.features import extract_features_from_flows
from beacon_detector.ops import (
    export_synthetic_normalized_csv,
    run_batch_score,
    run_rules_only_score,
    train_random_forest_model,
)
from beacon_detector.ops.grouping import build_operational_flows
from beacon_detector.ops.ingest import (
    load_netflow_ipfix_csv,
    load_operational_input,
    load_zeek_conn_log,
)
from beacon_detector.ops.model import (
    OpsGroupedValidationResult,
    OpsValidationPrediction,
    threshold_profile_metadata,
)
from beacon_detector.ops.schema import validate_normalized_csv

FIXTURE_ROOT = Path("data/operational/fixtures")


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
        self.assertEqual(summary["ingestion"]["input_row_count"], 5)
        self.assertEqual(summary["ingestion"]["loaded_event_count"], 5)
        self.assertEqual(summary["ingestion"]["skipped_row_count"], 0)
        self.assertIn("output_manifest", summary)
        self.assertIn("runtime_environment", summary)
        self.assertEqual(summary["output_manifest"][0]["path"], "alerts.csv")
        report = outputs.report_md.read_text(encoding="utf-8")
        self.assertIn("## Ingestion", report)
        self.assertIn("## Outputs", report)
        self.assertIn("## Model", report)

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

    def test_netflow_ipfix_csv_adapter_loads_common_field_aliases(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_netflow")
        path = output_dir / "netflow.csv"
        _write_netflow_csv(path)

        events = load_netflow_ipfix_csv(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].src_ip, "10.0.0.5")
        self.assertEqual(events[0].src_port, "1111")
        self.assertEqual(events[0].dst_ip, "203.0.113.10")
        self.assertEqual(events[0].dst_port, 443)
        self.assertEqual(events[0].protocol, "tcp")
        self.assertEqual(events[0].total_bytes, 150)
        self.assertEqual(events[0].total_packets, 3)
        self.assertEqual(events[0].duration_seconds, 1.0)

    def test_ipfix_csv_adapter_loads_information_element_names(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_ipfix")
        path = output_dir / "ipfix.csv"
        _write_ipfix_csv(path)

        events = load_netflow_ipfix_csv(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].src_ip, "10.0.0.5")
        self.assertEqual(events[0].dst_port, 443)
        self.assertEqual(events[0].protocol, "tcp")
        self.assertEqual(events[0].total_bytes, 150)
        self.assertEqual(events[0].duration_seconds, 1.0)

    def test_checked_in_netflow_fixture_loads_common_aliases_and_udp(self) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "netflow_common_aliases.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(result.diagnostics.input_row_count, 2)
        self.assertEqual(result.diagnostics.loaded_event_count, 2)
        self.assertEqual(result.diagnostics.skipped_row_count, 0)
        self.assertEqual(result.events[1].protocol, "udp")
        self.assertEqual(result.events[1].dst_port, 53)
        self.assertEqual(result.events[1].total_packets, 4)

    def test_checked_in_ipfix_fixture_loads_ipv6_information_elements(self) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "ipfix_information_elements_ipv6.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(result.diagnostics.input_row_count, 2)
        self.assertEqual(result.events[0].src_ip, "2001:db8::5")
        self.assertEqual(result.events[0].dst_ip, "2001:db8::10")
        self.assertEqual(result.events[0].protocol, "tcp")
        self.assertEqual(result.events[1].protocol, "udp")
        self.assertEqual(result.events[1].duration_seconds, 0.5)

    def test_checked_in_netflow_fixture_loads_iso_timestamps_without_optional_fields(
        self,
    ) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "netflow_iso_timestamps.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(result.diagnostics.loaded_event_count, 2)
        self.assertIsNone(result.events[0].total_packets)
        self.assertEqual(
            result.events[0].timestamp.isoformat(),
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(result.events[1].duration_seconds, 3.0)

    def test_checked_in_netflow_fixture_loads_transport_protocol_aliases(self) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "netflow_transport_protocol.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(result.diagnostics.loaded_event_count, 1)
        self.assertEqual(result.events[0].protocol, "tcp")
        self.assertEqual(result.events[0].dst_ip, "203.0.113.30")
        self.assertEqual(result.events[0].duration_seconds, 2.0)

    def test_checked_in_netflow_fixture_skips_unsupported_protocol_with_diagnostics(
        self,
    ) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "netflow_unsupported_protocol.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(result.diagnostics.input_row_count, 2)
        self.assertEqual(result.diagnostics.loaded_event_count, 1)
        self.assertEqual(result.diagnostics.skipped_row_count, 1)
        self.assertEqual(
            result.diagnostics.skipped_row_reasons,
            {"unsupported_protocol": 1},
        )

    def test_checked_in_zeek_fixture_skips_unsupported_protocol_with_diagnostics(
        self,
    ) -> None:
        result = load_operational_input(
            FIXTURE_ROOT / "zeek_unsupported_protocol.conn.log",
            input_format="zeek-conn",
        )

        self.assertEqual(result.diagnostics.input_row_count, 2)
        self.assertEqual(result.diagnostics.loaded_event_count, 1)
        self.assertEqual(result.diagnostics.skipped_row_count, 1)
        self.assertEqual(
            result.diagnostics.skipped_row_reasons,
            {"unsupported_protocol": 1},
        )

    def test_checked_in_netflow_missing_required_field_fails_clearly(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"NetFlow/IPFIX CSV row 2.*dst_ip, destination_ip, dstaddr",
        ):
            load_netflow_ipfix_csv(FIXTURE_ROOT / "netflow_missing_required.csv")

    def test_checked_in_netflow_invalid_port_fails_clearly(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"NetFlow/IPFIX CSV row 2: dst_port must be between 0 and 65535",
        ):
            load_netflow_ipfix_csv(FIXTURE_ROOT / "netflow_invalid_port.csv")

    def test_checked_in_netflow_negative_duration_fails_clearly(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"NetFlow/IPFIX CSV row 2: duration_seconds must be non-negative",
        ):
            load_netflow_ipfix_csv(FIXTURE_ROOT / "netflow_negative_duration.csv")

    def test_checked_in_header_only_inputs_fail_clearly(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"NetFlow/IPFIX CSV contains no data rows",
        ):
            load_netflow_ipfix_csv(FIXTURE_ROOT / "netflow_header_only.csv")
        with self.assertRaisesRegex(
            ValueError,
            r"Zeek conn\.log contains no data rows",
        ):
            load_zeek_conn_log(FIXTURE_ROOT / "zeek_header_only.conn.log")

    def test_checked_in_zeek_and_netflow_parity_match_events_features_and_scores(
        self,
    ) -> None:
        zeek = load_operational_input(
            FIXTURE_ROOT / "zeek_parity.conn.log",
            input_format="zeek-conn",
        )
        netflow = load_operational_input(
            FIXTURE_ROOT / "netflow_parity.csv",
            input_format="netflow-ipfix-csv",
        )

        self.assertEqual(
            [_event_signature(event) for event in zeek.events],
            [_event_signature(event) for event in netflow.events],
        )

        zeek_flows, _ = build_operational_flows(zeek.events)
        netflow_flows, _ = build_operational_flows(netflow.events)
        zeek_features = extract_features_from_flows(zeek_flows)
        netflow_features = extract_features_from_flows(netflow_flows)

        self.assertEqual(
            [_flow_signature(flow) for flow in zeek_flows],
            [_flow_signature(flow) for flow in netflow_flows],
        )
        self.assertEqual(
            [_feature_signature(row) for row in zeek_features],
            [_feature_signature(row) for row in netflow_features],
        )

        output_dir = _clean_output_dir("tests/.tmp/ops_parity")
        zeek_outputs = run_rules_only_score(
            input_path=FIXTURE_ROOT / "zeek_parity.conn.log",
            input_format="zeek-conn",
            output_dir=output_dir / "zeek",
        )
        netflow_outputs = run_rules_only_score(
            input_path=FIXTURE_ROOT / "netflow_parity.csv",
            input_format="netflow-ipfix-csv",
            output_dir=output_dir / "netflow",
        )

        self.assertEqual(
            _rows(zeek_outputs.alerts_csv),
            _rows(netflow_outputs.alerts_csv),
        )
        self.assertEqual(
            _rows(zeek_outputs.scored_flows_csv),
            _rows(netflow_outputs.scored_flows_csv),
        )

    def test_netflow_score_summary_includes_ingestion_diagnostics(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_netflow_diagnostics")

        outputs = run_rules_only_score(
            input_path=FIXTURE_ROOT / "netflow_unsupported_protocol.csv",
            input_format="netflow-ipfix-csv",
            output_dir=output_dir / "out",
        )

        summary = json.loads(outputs.run_summary_json.read_text(encoding="utf-8"))
        self.assertEqual(summary["ingestion"]["input_row_count"], 2)
        self.assertEqual(summary["ingestion"]["loaded_event_count"], 1)
        self.assertEqual(summary["ingestion"]["skipped_row_count"], 1)
        self.assertEqual(
            summary["ingestion"]["skipped_row_reasons"],
            {"unsupported_protocol": 1},
        )
        report = outputs.report_md.read_text(encoding="utf-8")
        self.assertIn("unsupported_protocol=1", report)

    def test_score_fails_when_no_supported_events_are_loaded(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_no_supported_rows")
        input_path = output_dir / "unsupported_only.csv"
        _write_csv(
            input_path,
            [
                {
                    "first_switched": "1767225600.000000",
                    "last_switched": "1767225601.000000",
                    "srcaddr": "10.0.0.5",
                    "srcport": "1111",
                    "dstaddr": "203.0.113.10",
                    "dstport": "443",
                    "proto": "1",
                    "bytes": "150",
                    "pkts": "3",
                }
            ],
        )

        with self.assertRaisesRegex(
            ValueError,
            r"No supported operational events were loaded",
        ):
            run_rules_only_score(
                input_path=input_path,
                input_format="netflow-ipfix-csv",
                output_dir=output_dir / "out",
            )

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

    def test_cli_score_accepts_netflow_ipfix_csv(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_cli_netflow")
        input_path = output_dir / "netflow.csv"
        _write_netflow_csv(input_path)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "beacon_detector.cli.ops",
                "score",
                "--input",
                str(input_path),
                "--input-format",
                "netflow-ipfix-csv",
                "--output-dir",
                str(output_dir / "out"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Operational scoring complete", completed.stdout)
        self.assertTrue((output_dir / "out" / "scored_flows.csv").exists())

    def test_checked_in_operational_example_scores_end_to_end(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_checked_in_example")
        score_path = Path("data/operational/example_score.csv")
        train_path = Path("data/operational/example_train.csv")

        self.assertTrue(validate_normalized_csv(score_path).is_valid)
        self.assertTrue(validate_normalized_csv(train_path, require_label=True).is_valid)

        training_outputs = train_random_forest_model(
            train_paths=[train_path],
            output_dir=output_dir / "model",
        )
        outputs = run_batch_score(
            input_path=score_path,
            input_format="normalized-csv",
            output_dir=output_dir / "out",
            model_artifact_path=training_outputs.model_dir,
            threshold_profile="balanced",
        )

        self.assertTrue(outputs.alerts_csv.exists())
        self.assertTrue(outputs.scored_flows_csv.exists())
        self.assertTrue(outputs.run_summary_json.exists())
        self.assertTrue(outputs.report_md.exists())

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
        self.assertTrue((output_dir / "model" / "artifact_manifest.json").exists())

    def test_cli_export_synthetic_writes_normalized_csv(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_cli_export_synthetic")
        output_path = output_dir / "synthetic.csv"

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "beacon_detector.cli.ops",
                "export-synthetic",
                "--output",
                str(output_path),
                "--normal-event-count",
                "24",
                "--normal-flow-count",
                "4",
                "--beacon-event-count",
                "6",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Synthetic normalized export complete", completed.stdout)
        self.assertTrue(output_path.exists())
        self.assertTrue(output_path.with_suffix(".metadata.json").exists())

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
        self.assertTrue(training_outputs.artifact_manifest_json.exists())
        metadata = json.loads(training_outputs.metadata_json.read_text(encoding="utf-8"))
        self.assertEqual(metadata["input_contract"], "normalized_csv_with_label")
        self.assertEqual(metadata["label_mapping"]["beacon"], 1)
        self.assertIn("runtime_environment", metadata)
        self.assertIn("scikit-learn", metadata["runtime_environment"]["dependency_versions"])
        self.assertEqual(metadata["persistence"]["format"], "pickle")
        self.assertEqual(metadata["skipped_unknown_event_count"], 1)
        self.assertEqual(metadata["validation"]["strategy"], "stratified_group_kfold")
        self.assertEqual(metadata["validation"]["executed_folds"], 2)
        self.assertEqual(len(metadata["validation"]["folds"]), 2)
        self.assertIn("mean_f1_score", metadata["validation"]["metrics"])
        self.assertEqual(
            metadata["calibration"]["probability_calibration"],
            "not_applied_diagnostics_only",
        )
        self.assertFalse(metadata["calibration"]["supports_probability_language"])
        self.assertEqual(
            metadata["calibration"]["out_of_fold_prediction_count"],
            metadata["validation"]["out_of_fold_prediction_count"],
        )
        self.assertIsNotNone(metadata["calibration"]["brier_score"])
        self.assertEqual(len(metadata["calibration"]["reliability_bins"]), 10)
        self.assertEqual(
            set(metadata["threshold_profiles"]),
            {"conservative", "balanced", "sensitive"},
        )
        self.assertEqual(
            metadata["threshold_profiles"]["balanced"]["selection_method"],
            "out_of_fold_grouped_validation",
        )
        manifest = json.loads(
            training_outputs.artifact_manifest_json.read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["artifact_type"], "operational_random_forest_model")
        self.assertEqual(manifest["label_mapping"]["unknown"], "skipped")
        self.assertIn("calibration", manifest)
        self.assertIn("threshold_profiles", manifest)
        training_report = training_outputs.training_report_md.read_text(
            encoding="utf-8"
        )
        self.assertIn("## Calibration Diagnostics", training_report)
        self.assertIn("Brier score:", training_report)
        self.assertIn(
            "Use RF scores for ranking and thresholding, not as calibrated probabilities.",
            training_report,
        )

        outputs = run_batch_score(
            input_path=score_path,
            input_format="normalized-csv",
            output_dir=output_dir / "out",
            model_artifact_path=training_outputs.model_dir,
            threshold_profile="balanced",
        )

        summary = json.loads(outputs.run_summary_json.read_text(encoding="utf-8"))
        self.assertEqual(summary["mode"], "rules_random_forest_hybrid")
        self.assertEqual(summary["alert_profile"], "balanced")
        self.assertEqual(summary["threshold_profile"]["source"], "model_artifact")
        self.assertEqual(summary["model_detector_name"], "random_forest_v1")
        self.assertIn("model_metadata", summary)
        self.assertEqual(summary["model_metadata"]["label_mapping"]["beacon"], 1)
        self.assertEqual(
            summary["model_metadata"]["calibration"]["probability_calibration"],
            "not_applied_diagnostics_only",
        )
        self.assertIn("rf_score", summary["score_semantics"])
        self.assertIn("confidence", summary["score_semantics"])
        self.assertIn(
            "Uncalibrated Random Forest beacon score",
            summary["score_semantics"]["rf_score"],
        )
        self.assertIn(
            "not a calibrated probability",
            summary["score_semantics"]["confidence"],
        )
        scored_rows = _rows(outputs.scored_flows_csv)
        self.assertEqual(scored_rows[0]["detector_mode"], "rules_random_forest_hybrid")
        self.assertNotEqual(scored_rows[0]["rf_score"], "")
        score_report = outputs.report_md.read_text(encoding="utf-8")
        self.assertIn("Calibration status:", score_report)
        self.assertIn(
            "RF scores are uncalibrated model scores.",
            score_report,
        )
        self.assertIn("random forest score", score_report)
        self.assertNotIn("random forest probability", score_report)

    def test_threshold_profiles_keep_expected_validation_tradeoff_order(self) -> None:
        profiles = threshold_profile_metadata(
            OpsGroupedValidationResult(
                strategy="stratified_group_kfold",
                requested_folds=3,
                executed_folds=3,
                skipped_reason=None,
                folds=(),
                predictions=(
                    OpsValidationPrediction(1, "benign", 0.10),
                    OpsValidationPrediction(1, "benign", 0.20),
                    OpsValidationPrediction(2, "benign", 0.30),
                    OpsValidationPrediction(2, "benign", 0.40),
                    OpsValidationPrediction(2, "benign", 0.45),
                    OpsValidationPrediction(3, "benign", 0.50),
                    OpsValidationPrediction(3, "benign", 0.70),
                    OpsValidationPrediction(1, "beacon", 0.25),
                    OpsValidationPrediction(1, "beacon", 0.60),
                    OpsValidationPrediction(2, "beacon", 0.65),
                    OpsValidationPrediction(3, "beacon", 0.80),
                ),
            )
        )

        conservative = profiles["conservative"]
        balanced = profiles["balanced"]
        sensitive = profiles["sensitive"]
        self.assertGreaterEqual(conservative["threshold"], balanced["threshold"])
        self.assertLessEqual(sensitive["threshold"], balanced["threshold"])
        self.assertGreaterEqual(
            sensitive["metrics"]["recall"],
            conservative["metrics"]["recall"],
        )
        self.assertGreaterEqual(
            len(
                {
                    conservative["threshold"],
                    balanced["threshold"],
                    sensitive["threshold"],
                }
            ),
            2,
        )
        for profile in profiles.values():
            self.assertIn("selection_method", profile)

    def test_synthetic_export_writes_labelled_normalized_training_csv(self) -> None:
        output_dir = _clean_output_dir("tests/.tmp/ops_synthetic_export")
        output_path = output_dir / "synthetic_normalized.csv"

        export = export_synthetic_normalized_csv(
            output_path=output_path,
            config=SyntheticTrafficConfig(
                start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                seed=99,
                normal_event_count=24,
                normal_flow_count=4,
                normal_events_per_flow_min=4,
                normal_events_per_flow_max=6,
                beacon_event_count=6,
            ),
        )

        self.assertTrue(export.output_csv.exists())
        self.assertTrue(export.metadata_json.exists())
        validation = validate_normalized_csv(output_path, require_label=True)
        self.assertTrue(validation.is_valid)
        rows = _rows(output_path)
        self.assertIn("scenario_name", rows[0])
        self.assertIn("benign", {row["label"] for row in rows})
        self.assertIn("beacon", {row["label"] for row in rows})

        training_outputs = train_random_forest_model(
            train_paths=[output_path],
            output_dir=output_dir / "model",
        )
        self.assertTrue(training_outputs.model_file.exists())


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


def _write_netflow_csv(path: Path) -> None:
    rows = [
        {
            "first_switched": "1767225600.000000",
            "last_switched": "1767225601.000000",
            "srcaddr": "10.0.0.5",
            "srcport": "1111",
            "dstaddr": "203.0.113.10",
            "dstport": "443",
            "proto": "6",
            "bytes": "150",
            "pkts": "3",
        },
        {
            "first_switched": "1767225660.000000",
            "last_switched": "1767225661.500000",
            "srcaddr": "10.0.0.5",
            "srcport": "2222",
            "dstaddr": "203.0.113.10",
            "dstport": "443",
            "proto": "6",
            "bytes": "150",
            "pkts": "3",
        },
        {
            "first_switched": "1767225660.000000",
            "last_switched": "1767225661.500000",
            "srcaddr": "10.0.0.5",
            "srcport": "2222",
            "dstaddr": "203.0.113.10",
            "dstport": "0",
            "proto": "1",
            "bytes": "150",
            "pkts": "3",
        },
    ]
    _write_csv(path, rows)


def _write_ipfix_csv(path: Path) -> None:
    rows = [
        {
            "flowStartMilliseconds": "1767225600000",
            "flowEndMilliseconds": "1767225601000",
            "sourceIPv4Address": "10.0.0.5",
            "sourceTransportPort": "1111",
            "destinationIPv4Address": "203.0.113.10",
            "destinationTransportPort": "443",
            "protocolIdentifier": "6",
            "octetDeltaCount": "150",
            "packetDeltaCount": "3",
        },
        {
            "flowStartMilliseconds": "1767225660000",
            "flowEndMilliseconds": "1767225661000",
            "sourceIPv4Address": "10.0.0.5",
            "sourceTransportPort": "2222",
            "destinationIPv4Address": "203.0.113.10",
            "destinationTransportPort": "443",
            "protocolIdentifier": "tcp",
            "octetDeltaCount": "150",
            "packetDeltaCount": "3",
        },
    ]
    _write_csv(path, rows)


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _event_signature(event) -> tuple[object, ...]:
    return (
        event.timestamp.isoformat(),
        event.src_ip,
        event.src_port,
        event.direction,
        event.dst_ip,
        event.dst_port,
        event.protocol,
        event.total_bytes,
        event.duration_seconds,
        event.total_packets,
    )


def _flow_signature(flow) -> tuple[object, ...]:
    return (
        flow.flow_key.src_ip,
        flow.flow_key.direction,
        flow.flow_key.dst_ip,
        flow.flow_key.dst_port,
        flow.flow_key.protocol,
        flow.start_time.isoformat(),
        flow.end_time.isoformat(),
        len(flow.events),
    )


def _feature_signature(row) -> tuple[object, ...]:
    return (
        row.flow_key.src_ip,
        row.flow_key.direction,
        row.flow_key.dst_ip,
        row.flow_key.dst_port,
        row.flow_key.protocol,
        row.label,
        row.event_count,
        row.total_bytes,
        row.flow_duration_seconds,
        row.mean_interarrival_seconds,
        row.inter_arrival_cv,
        row.periodicity_score,
        row.size_cv,
    )


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
