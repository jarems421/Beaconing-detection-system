from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from beacon_detector.evaluation.ctu13 import (
    Ctu13DetectorEvaluation,
    Ctu13EvaluationConfig,
    Ctu13EvaluationResult,
    Ctu13FeatureDataset,
    Ctu13PredictionRecord,
    Ctu13ScenarioInput,
    build_ctu13_feature_dataset,
    export_ctu13_multi_scenario_tables,
    run_ctu13_multi_scenario_evaluation,
)
from beacon_detector.evaluation.metrics import calculate_classification_metrics
from beacon_detector.flows import build_flows
from beacon_detector.parsing import (
    Ctu13LabelPolicy,
    Ctu13ParseSummary,
    ctu13_feature_transfer_summary,
    load_ctu13_binetflow_events,
    map_ctu13_label,
)


class Ctu13AdapterTests(unittest.TestCase):
    def test_label_mapping_defaults_skip_ambiguous_labels(self) -> None:
        policy = Ctu13LabelPolicy()

        self.assertEqual(map_ctu13_label("flow=From-Botnet-V42-TCP", policy), "beacon")
        self.assertEqual(map_ctu13_label("flow=From-Normal-V42-Grill", policy), "benign")
        self.assertEqual(map_ctu13_label("flow=Background-UDP-Established", policy), "skip")
        self.assertEqual(map_ctu13_label("flow=To-Botnet-V42-TCP", policy), "skip")
        self.assertEqual(map_ctu13_label("flow=To-Normal-V42-TCP", policy), "skip")

    def test_label_mapping_can_include_background_as_benign(self) -> None:
        policy = Ctu13LabelPolicy(include_background_as_benign=True)

        self.assertEqual(map_ctu13_label("flow=Background", policy), "benign")

    def test_load_ctu13_binetflow_events_maps_supported_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.binetflow"
            _write_sample_binetflow(path)

            result = load_ctu13_binetflow_events(path, scenario_name="ctu13_test")

        self.assertEqual(result.summary.total_rows, 5)
        self.assertEqual(result.summary.parsed_events, 3)
        self.assertEqual(result.summary.mapped_label_counts["beacon"], 2)
        self.assertEqual(result.summary.mapped_label_counts["benign"], 1)
        self.assertIn("label:ctu13_background", result.summary.skip_reason_counts)

        events = result.events
        self.assertEqual(events[0].protocol, "tcp")
        self.assertEqual(events[0].src_port, "1234")
        self.assertEqual(events[0].direction, "->")
        self.assertEqual(events[0].dst_port, 80)
        self.assertEqual(events[0].size_bytes, 500)
        self.assertEqual(events[0].label, "beacon")
        self.assertEqual(events[0].scenario_name, "ctu13_test:ctu13_from_botnet")

    def test_ctu13_rows_can_feed_existing_flow_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.binetflow"
            _write_sample_binetflow(path)
            result = load_ctu13_binetflow_events(path, scenario_name="ctu13_test")

        flows = build_flows(result.events)
        repeated_flow = next(flow for flow in flows if flow.flow_key.dst_port == 80)

        self.assertEqual(repeated_flow.event_count, 2)
        self.assertEqual(repeated_flow.label, "beacon")
        self.assertEqual(repeated_flow.total_bytes, 1100)

    def test_ctu13_source_port_and_direction_prevent_unrelated_merges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.binetflow"
            rows = [
                _ctu_row("2011/08/10 09:47:50.000000", sport="1234", direction="  ->"),
                _ctu_row("2011/08/10 09:47:55.000000", sport="5678", direction="  ->"),
                _ctu_row("2011/08/10 09:48:00.000000", sport="1234", direction="  <-"),
            ]
            _write_binetflow_rows(path, rows)

            result = load_ctu13_binetflow_events(path, scenario_name="ctu13_test")

        flows = build_flows(result.events)

        self.assertEqual(len(flows), 3)
        self.assertEqual({flow.flow_key.src_port for flow in flows}, {"1234", "5678"})
        self.assertEqual({flow.flow_key.direction for flow in flows}, {"->", "<-"})

    def test_ctu13_feature_dataset_drops_mixed_label_grouped_flows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "mixed.binetflow"
            rows = [
                _ctu_row(
                    "2011/08/10 09:47:50.000000",
                    label="flow=From-Normal-V42-TCP",
                ),
                _ctu_row(
                    "2011/08/10 09:47:55.000000",
                    label="flow=From-Botnet-V42-TCP",
                ),
            ]
            _write_binetflow_rows(path, rows)

            dataset = build_ctu13_feature_dataset(
                Ctu13EvaluationConfig(input_path=path, scenario_name="ctu13_test")
            )

        self.assertEqual(dataset.dropped_mixed_label_flow_count, 1)
        self.assertEqual(dataset.feature_rows, ())

    def test_ctu13_reference_split_is_stable_under_row_reordering(self) -> None:
        rows = [
            _ctu_row(
                f"2011/08/10 09:47:{50 + index:02d}.000000",
                sport=str(2000 + index),
                label="flow=From-Normal-V42-TCP",
            )
            for index in range(6)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            first_path = Path(temp_dir) / "ordered.binetflow"
            second_path = Path(temp_dir) / "reversed.binetflow"
            _write_binetflow_rows(first_path, rows)
            _write_binetflow_rows(second_path, list(reversed(rows)))

            first = build_ctu13_feature_dataset(
                Ctu13EvaluationConfig(input_path=first_path, scenario_name="ctu13_test")
            )
            second = build_ctu13_feature_dataset(
                Ctu13EvaluationConfig(input_path=second_path, scenario_name="ctu13_test")
            )

        self.assertEqual(
            {row.flow_key for row in first.reference_benign_rows},
            {row.flow_key for row in second.reference_benign_rows},
        )

    def test_background_sensitivity_can_cap_background_feature_rows(self) -> None:
        rows = [
            _ctu_row(
                "2011/08/10 09:47:50.000000",
                sport="1001",
                label="flow=Background",
            ),
            _ctu_row(
                "2011/08/10 09:47:55.000000",
                sport="1002",
                label="flow=Background",
            ),
            _ctu_row(
                "2011/08/10 09:48:00.000000",
                sport="1003",
                label="flow=Background",
            ),
            _ctu_row(
                "2011/08/10 09:48:05.000000",
                sport="2001",
                label="flow=From-Normal-CVUT",
            ),
            _ctu_row(
                "2011/08/10 09:48:10.000000",
                sport="3001",
                label="flow=From-Botnet-V42",
            ),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.binetflow"
            _write_binetflow_rows(path, rows)
            dataset = build_ctu13_feature_dataset(
                Ctu13EvaluationConfig(
                    input_path=path,
                    scenario_name="ctu13_test",
                    label_policy=Ctu13LabelPolicy(include_background_as_benign=True),
                    max_background_benign_feature_rows=1,
                )
            )

        self.assertEqual(dataset.capped_background_benign_flow_count, 2)
        self.assertEqual(
            sum(
                1
                for row in dataset.feature_rows
                if (row.scenario_name or "").endswith(":ctu13_background")
            ),
            1,
        )
        self.assertTrue(any(row.label == "beacon" for row in dataset.feature_rows))

    def test_feature_transfer_summary_documents_schema_mismatch(self) -> None:
        rows = ctu13_feature_transfer_summary()
        statuses = {row["transfer_status"] for row in rows}

        self.assertIn("derived_from_repeated_flow_records", statuses)
        self.assertIn("not_used_in_current_detectors", statuses)

    def test_multi_scenario_evaluation_runs_conservative_and_sensitivity_policies(self) -> None:
        scenarios = [
            Ctu13ScenarioInput(Path("scenario_a.binetflow"), "ctu13_a"),
            Ctu13ScenarioInput(Path("scenario_b.binetflow"), "ctu13_b"),
        ]

        with patch(
            "beacon_detector.evaluation.ctu13.run_ctu13_evaluation",
            side_effect=_fake_ctu13_evaluation,
        ) as run_single:
            result = run_ctu13_multi_scenario_evaluation(
                scenarios=scenarios,
                output_dir="unused",
                include_background_sensitivity=True,
            )

        self.assertEqual(run_single.call_count, 4)
        called_configs = [call.args[0] for call in run_single.call_args_list]
        self.assertEqual(
            [config.max_background_benign_feature_rows for config in called_configs],
            [None, None, 10_000, 10_000],
        )
        self.assertEqual(result.conservative_result.policy_name, "conservative")
        self.assertIsNotNone(result.background_sensitivity_result)
        self.assertFalse(
            result.conservative_result.label_policy.include_background_as_benign
        )
        self.assertTrue(
            result.background_sensitivity_result.label_policy.include_background_as_benign
        )
        self.assertEqual(len(result.conservative_result.detector_results), 1)
        combined_metrics = result.conservative_result.detector_results[0].metrics
        self.assertEqual(combined_metrics.confusion_matrix.true_positive, 2)

    def test_multi_scenario_evaluation_combines_per_scenario_operating_points(self) -> None:
        scenarios = [
            Ctu13ScenarioInput(Path("scenario_a.binetflow"), "ctu13_a"),
            Ctu13ScenarioInput(Path("scenario_b.binetflow"), "ctu13_b"),
        ]

        with patch(
            "beacon_detector.evaluation.ctu13.run_ctu13_evaluation",
            side_effect=_fake_ctu13_evaluation_with_scenario_threshold,
        ):
            result = run_ctu13_multi_scenario_evaluation(
                scenarios=scenarios,
                output_dir="unused",
                include_background_sensitivity=False,
            )

        self.assertEqual(len(result.conservative_result.detector_results), 1)
        detector_result = result.conservative_result.detector_results[0]
        self.assertEqual(detector_result.detector_name, "fake_detector")
        self.assertIn("per_scenario_calibrated", detector_result.operating_point)
        self.assertEqual(len(detector_result.records), 4)

    def test_multi_scenario_exports_include_label_policy_sensitivity(self) -> None:
        scenarios = [Ctu13ScenarioInput(Path("scenario_a.binetflow"), "ctu13_a")]
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "beacon_detector.evaluation.ctu13.run_ctu13_evaluation",
                side_effect=_fake_ctu13_evaluation,
            ):
                result = run_ctu13_multi_scenario_evaluation(
                    scenarios=scenarios,
                    output_dir=temp_dir,
                    include_background_sensitivity=True,
                )
            written_paths = export_ctu13_multi_scenario_tables(result)

            written_names = {path.name for path in written_paths}
            self.assertIn("ctu13_label_policy_sensitivity.csv", written_names)
            sensitivity_path = Path(temp_dir) / "ctu13_label_policy_sensitivity.csv"
            self.assertIn(
                "background_as_benign_sensitivity",
                sensitivity_path.read_text(encoding="utf-8"),
            )


def _write_sample_binetflow(path: Path) -> None:
    rows = [
        {
            "StartTime": "2011/08/10 09:46:53.047277",
            "Dur": "1.0",
            "Proto": "tcp",
            "SrcAddr": "147.32.84.165",
            "Sport": "1234",
            "Dir": "  ->",
            "DstAddr": "1.2.3.4",
            "Dport": "80",
            "State": "CON",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "5",
            "TotBytes": "500",
            "SrcBytes": "300",
            "Label": "flow=From-Botnet-V42-TCP-Established",
        },
        {
            "StartTime": "2011/08/10 09:47:53.047277",
            "Dur": "1.0",
            "Proto": "tcp",
            "SrcAddr": "147.32.84.165",
            "Sport": "1234",
            "Dir": "  ->",
            "DstAddr": "1.2.3.4",
            "Dport": "http",
            "State": "CON",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "6",
            "TotBytes": "600",
            "SrcBytes": "350",
            "Label": "flow=From-Botnet-V42-TCP-Established",
        },
        {
            "StartTime": "2011/08/10 09:48:00.000000",
            "Dur": "1.0",
            "Proto": "udp",
            "SrcAddr": "147.32.84.170",
            "Sport": "5555",
            "Dir": "  <->",
            "DstAddr": "8.8.8.8",
            "Dport": "domain",
            "State": "CON",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "2",
            "TotBytes": "120",
            "SrcBytes": "60",
            "Label": "flow=From-Normal-V42-Grill",
        },
        {
            "StartTime": "2011/08/10 09:49:00.000000",
            "Dur": "1.0",
            "Proto": "udp",
            "SrcAddr": "10.0.0.1",
            "Sport": "123",
            "Dir": "  <->",
            "DstAddr": "10.0.0.2",
            "Dport": "123",
            "State": "CON",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "2",
            "TotBytes": "120",
            "SrcBytes": "60",
            "Label": "flow=Background",
        },
        {
            "StartTime": "2011/08/10 09:50:00.000000",
            "Dur": "1.0",
            "Proto": "icmp",
            "SrcAddr": "147.32.84.165",
            "Sport": "",
            "Dir": "  <->",
            "DstAddr": "1.2.3.4",
            "Dport": "",
            "State": "CON",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "2",
            "TotBytes": "120",
            "SrcBytes": "60",
            "Label": "flow=From-Botnet-V42-ICMP",
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _ctu_row(
    start_time: str,
    *,
    sport: str = "1234",
    direction: str = "  ->",
    label: str = "flow=From-Botnet-V42-TCP-Established",
) -> dict[str, str]:
    return {
        "StartTime": start_time,
        "Dur": "1.0",
        "Proto": "tcp",
        "SrcAddr": "147.32.84.165",
        "Sport": sport,
        "Dir": direction,
        "DstAddr": "1.2.3.4",
        "Dport": "80",
        "State": "CON",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": "5",
        "TotBytes": "500",
        "SrcBytes": "300",
        "Label": label,
    }


def _write_binetflow_rows(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _fake_ctu13_evaluation(config: Ctu13EvaluationConfig, **_) -> Ctu13EvaluationResult:
    return _fake_ctu13_evaluation_result(config, operating_point="fake")


def _fake_ctu13_evaluation_with_scenario_threshold(
    config: Ctu13EvaluationConfig, **_
) -> Ctu13EvaluationResult:
    return _fake_ctu13_evaluation_result(
        config,
        operating_point=f"threshold={config.scenario_name}",
    )


def _fake_ctu13_evaluation_result(
    config: Ctu13EvaluationConfig,
    *,
    operating_point: str,
) -> Ctu13EvaluationResult:
    records = [
        _prediction_record(config.scenario_name, "beacon", "beacon", 0.9),
        _prediction_record(config.scenario_name, "benign", "beacon", 0.7),
    ]
    detector_result = Ctu13DetectorEvaluation(
        detector_name="fake_detector",
        operating_point=operating_point,
        metrics=calculate_classification_metrics(
            [record.true_label for record in records],
            [record.predicted_label for record in records],
        ),
        records=tuple(records),
    )
    return Ctu13EvaluationResult(
        config=config,
        dataset=Ctu13FeatureDataset(
            feature_rows=(),
            reference_benign_rows=(),
            evaluation_rows=(),
            parse_summary=Ctu13ParseSummary(
                source_path=str(config.input_path),
                scenario_name=config.scenario_name,
                total_rows=2,
                parsed_events=2,
                skipped_rows=0,
                raw_label_counts={},
                mapped_label_counts={},
                skip_reason_counts={},
            ),
        ),
        detector_results=(detector_result,),
    )


def _prediction_record(
    scenario_name: str,
    true_label: str,
    predicted_label: str,
    score: float,
) -> Ctu13PredictionRecord:
    label_group = "ctu13_from_botnet" if true_label == "beacon" else "ctu13_from_normal"
    return Ctu13PredictionRecord(
        detector_name="fake_detector",
        operating_point="fake",
        ctu_scenario=scenario_name,
        label_group=label_group,
        scenario_name=f"{scenario_name}:{label_group}",
        true_label=true_label,
        predicted_label=predicted_label,
        score=score,
        event_count=3,
        protocol="tcp",
        dst_port=80,
        total_bytes=1000,
        flow_duration_seconds=60.0,
        mean_size_bytes=500.0,
        size_cv=0.1,
        triggered_rules=(),
    )


if __name__ == "__main__":
    unittest.main()
