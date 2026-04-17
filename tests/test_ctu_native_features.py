from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from beacon_detector.evaluation.ctu13 import Ctu13ScenarioInput
from beacon_detector.evaluation.ctu13_native import (
    CtuNativeComparisonResult,
    CtuNativeDetectorResult,
    export_ctu_native_comparison_tables,
)
from beacon_detector.evaluation.metrics import calculate_classification_metrics
from beacon_detector.features.ctu_native import (
    native_features_from_ctu13_record,
    service_bucket,
)
from beacon_detector.parsing.ctu13 import Ctu13FlowRecord


class CtuNativeFeatureTests(unittest.TestCase):
    def test_native_features_use_ctu_fields_directly(self) -> None:
        row = native_features_from_ctu13_record(
            _record(),
            scenario_name="ctu13_test",
        )

        self.assertEqual(row.duration_seconds, 10.0)
        self.assertEqual(row.total_packets, 5)
        self.assertEqual(row.total_bytes, 1000)
        self.assertEqual(row.src_bytes, 300)
        self.assertEqual(row.dst_bytes, 700)
        self.assertAlmostEqual(row.src_byte_ratio or 0.0, 0.3)
        self.assertAlmostEqual(row.bytes_per_second or 0.0, 100.0)
        self.assertAlmostEqual(row.packets_per_second or 0.0, 0.5)
        self.assertEqual(row.protocol_tcp, 1)
        self.assertEqual(row.is_web_port, 1)

    def test_service_bucket_is_explicit(self) -> None:
        self.assertEqual(service_bucket(53), "dns_53")
        self.assertEqual(service_bucket(80), "http_80")
        self.assertEqual(service_bucket(13363), "ctu_common_13363")
        self.assertEqual(service_bucket(65000), "ephemeral_49152_plus")

    def test_native_comparison_export_marks_incompatible_detectors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            native_row = native_features_from_ctu13_record(
                _record(),
                scenario_name="ctu13_test",
            )
            records = (
                {
                    "scenario_name": "ctu13_test",
                    "true_label": "beacon",
                    "predicted_label": "beacon",
                },
            )
            result = CtuNativeComparisonResult(
                scenarios=(
                    Ctu13ScenarioInput(
                        input_path=Path("sample.binetflow"),
                        scenario_name="ctu13_test",
                    ),
                ),
                output_dir=Path(temp_dir),
                conservative_rows=(native_row,),
                background_rows=(native_row,),
                transferred_result_path=None,
                detector_results=(
                    CtuNativeDetectorResult(
                        detector_name="rule_baseline_v2_hardened_final",
                        operating_point="threshold=2.8",
                        feature_path="ctu_native",
                        compatibility_status="not_schema_compatible",
                        compatibility_notes="not compatible",
                        metrics=None,
                        records=(),
                    ),
                    CtuNativeDetectorResult(
                        detector_name="local_outlier_factor_v1",
                        operating_point="ctu_native",
                        feature_path="ctu_native",
                        compatibility_status="compatible_unsupervised_reference",
                        compatibility_notes="compatible",
                        metrics=calculate_classification_metrics(
                            [record["true_label"] for record in records],
                            [record["predicted_label"] for record in records],
                        ),
                        records=records,
                    ),
                ),
            )

            written_paths = export_ctu_native_comparison_tables(result)
            written_names = {path.name for path in written_paths}
            self.assertIn("ctu_native_detector_comparison.csv", written_names)
            detector_text = (Path(temp_dir) / "ctu_native_detector_comparison.csv").read_text(
                encoding="utf-8"
            )
            self.assertIn("not_schema_compatible", detector_text)


def _record() -> Ctu13FlowRecord:
    from datetime import datetime, timezone

    return Ctu13FlowRecord(
        start_time=datetime(2011, 8, 10, tzinfo=timezone.utc),
        duration_seconds=10.0,
        protocol="tcp",
        src_ip="10.0.0.1",
        src_port="12345",
        direction="->",
        dst_ip="10.0.0.2",
        dst_port=80,
        state="CON",
        total_packets=5,
        total_bytes=1000,
        src_bytes=300,
        raw_label="flow=From-Botnet-Test",
        mapped_label="beacon",
        label_category="ctu13_from_botnet",
    )


if __name__ == "__main__":
    unittest.main()
