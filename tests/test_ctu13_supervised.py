from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from beacon_detector.cli.score import score_ctu13_file
from beacon_detector.evaluation.ctu13 import Ctu13ScenarioInput
from beacon_detector.evaluation.ctu13_supervised import (
    WITHIN_CTU_SUPERVISED_STAGE,
    CtuSupervisedConfig,
    build_leave_one_scenario_splits,
    export_ctu_supervised_tables,
    fit_ctu_native_supervised_detector,
    predict_ctu_native_supervised,
    run_ctu_supervised_evaluation,
)
from beacon_detector.features.ctu_native import native_features_from_ctu13_record
from beacon_detector.parsing.ctu13 import Ctu13FlowRecord


class Ctu13SupervisedTests(unittest.TestCase):
    def test_leave_one_scenario_splits_hold_out_each_scenario_without_leakage(self) -> None:
        scenarios = [
            Ctu13ScenarioInput(Path("s5.binetflow"), "scenario_5"),
            Ctu13ScenarioInput(Path("s7.binetflow"), "scenario_7"),
            Ctu13ScenarioInput(Path("s11.binetflow"), "scenario_11"),
        ]

        splits = build_leave_one_scenario_splits(scenarios)

        self.assertEqual(
            {split.test_scenario_name for split in splits},
            {"scenario_5", "scenario_7", "scenario_11"},
        )
        for split in splits:
            self.assertNotIn(split.test_scenario_name, split.train_scenario_names)
            self.assertEqual(len(split.train_scenario_names), 2)

    def test_fit_predict_ctu_native_supervised_rows(self) -> None:
        rows = [
            _native_row("scenario_5", "beacon", total_bytes=5000, dst_port=13363),
            _native_row("scenario_5", "beacon", total_bytes=5200, dst_port=13363),
            _native_row("scenario_5", "benign", total_bytes=300, dst_port=80),
            _native_row("scenario_5", "benign", total_bytes=350, dst_port=80),
        ]
        config = CtuSupervisedConfig(random_forest_estimators=10)

        model = fit_ctu_native_supervised_detector(
            rows, detector_type="random_forest", config=config
        )
        predictions = predict_ctu_native_supervised(rows, model=model)

        self.assertEqual(len(predictions), len(rows))
        self.assertTrue(all(0.0 <= score <= 1.0 for _, score, _ in predictions))
        self.assertTrue({label for _, _, label in predictions}.issubset({"benign", "beacon"}))

    def test_exported_ctu_supervised_tables_include_policy_and_story_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            scenarios = _write_three_scenarios(temp_path)
            result = run_ctu_supervised_evaluation(
                scenarios=scenarios,
                output_dir=temp_path / "out",
                include_background_sensitivity=True,
                config=CtuSupervisedConfig(random_forest_estimators=10),
            )
            written_paths = export_ctu_supervised_tables(result)

            self.assertIn(
                "ctu_supervised_detector_comparison.csv", {path.name for path in written_paths}
            )
            detector_text = (
                temp_path / "out" / "ctu_supervised_detector_comparison.csv"
            ).read_text(encoding="utf-8")
            self.assertIn(WITHIN_CTU_SUPERVISED_STAGE, detector_text)
            sensitivity_text = (
                temp_path / "out" / "ctu_supervised_label_policy_sensitivity.csv"
            ).read_text(encoding="utf-8")
            self.assertIn("background_as_benign_sensitivity", sensitivity_text)
            metadata = json.loads(
                (temp_path / "out" / "ctu_supervised_metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["split_strategy"], "leave_one_ctu_scenario_out")
            self.assertEqual(len(metadata["splits"]), 3)
            self.assertIn(WITHIN_CTU_SUPERVISED_STAGE, metadata["related_story_stages"])

    def test_cli_score_writes_scored_csv_and_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            scenarios = _write_three_scenarios(temp_path)
            output_dir = temp_path / "scored"

            outputs = score_ctu13_file(
                input_path=scenarios[0].input_path,
                input_format="ctu13-binetflow",
                detector="ctu-native-random-forest",
                train_scenarios={
                    scenarios[1].scenario_name: scenarios[1].input_path,
                    scenarios[2].scenario_name: scenarios[2].input_path,
                },
                output_dir=output_dir,
                scenario_name=scenarios[0].scenario_name,
                config=CtuSupervisedConfig(random_forest_estimators=10),
            )

            self.assertTrue(outputs["scored_csv"].exists())
            self.assertTrue(outputs["summary_json"].exists())
            self.assertTrue(outputs["summary_md"].exists())
            self.assertIn("predicted_label", outputs["scored_csv"].read_text(encoding="utf-8"))
            summary = json.loads(outputs["summary_json"].read_text(encoding="utf-8"))
            self.assertEqual(summary["detector"], "ctu-native-random-forest")


def _write_three_scenarios(root: Path) -> list[Ctu13ScenarioInput]:
    scenarios: list[Ctu13ScenarioInput] = []
    for scenario_name, offset in (("scenario_5", 0), ("scenario_7", 10), ("scenario_11", 20)):
        path = root / f"{scenario_name}.binetflow"
        _write_binetflow(path, offset=offset)
        scenarios.append(Ctu13ScenarioInput(path, scenario_name))
    return scenarios


def _write_binetflow(path: Path, *, offset: int) -> None:
    rows = [
        _row(
            "2011/08/10 09:46:53.047277",
            "tcp",
            13363,
            20 + offset,
            6000 + offset,
            5000 + offset,
            "flow=From-Botnet-Test",
        ),
        _row(
            "2011/08/10 09:46:54.047277",
            "tcp",
            13363,
            22 + offset,
            6200 + offset,
            5100 + offset,
            "flow=From-Botnet-Test",
        ),
        _row(
            "2011/08/10 09:47:53.047277",
            "tcp",
            80,
            5 + offset,
            500 + offset,
            200 + offset,
            "flow=From-Normal-Test",
        ),
        _row(
            "2011/08/10 09:47:54.047277",
            "udp",
            53,
            3 + offset,
            180 + offset,
            80 + offset,
            "flow=From-Normal-Test",
        ),
        _row(
            "2011/08/10 09:48:54.047277",
            "udp",
            123,
            2 + offset,
            120 + offset,
            60 + offset,
            "flow=Background",
        ),
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _row(
    start_time: str,
    proto: str,
    dport: int,
    total_packets: int,
    total_bytes: int,
    src_bytes: int,
    label: str,
) -> dict[str, str]:
    return {
        "StartTime": start_time,
        "Dur": "1.0",
        "Proto": proto,
        "SrcAddr": "147.32.84.165",
        "Sport": "1234",
        "Dir": "  ->",
        "DstAddr": "1.2.3.4",
        "Dport": str(dport),
        "State": "CON",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": str(total_packets),
        "TotBytes": str(total_bytes),
        "SrcBytes": str(src_bytes),
        "Label": label,
    }


def _native_row(
    scenario_name: str,
    label: str,
    *,
    total_bytes: int,
    dst_port: int,
):
    from datetime import datetime, timezone

    label_group = "ctu13_from_botnet" if label == "beacon" else "ctu13_from_normal"
    record = Ctu13FlowRecord(
        start_time=datetime(2011, 8, 10, tzinfo=timezone.utc),
        duration_seconds=5.0,
        protocol="tcp",
        src_ip="10.0.0.1",
        src_port="12345",
        direction="->",
        dst_ip="10.0.0.2",
        dst_port=dst_port,
        state="CON",
        total_packets=10,
        total_bytes=total_bytes,
        src_bytes=int(total_bytes * 0.8),
        raw_label=f"flow={'From-Botnet' if label == 'beacon' else 'From-Normal'}-Test",
        mapped_label=label,
        label_category=label_group,
    )
    return native_features_from_ctu13_record(record, scenario_name=scenario_name)


if __name__ == "__main__":
    unittest.main()
