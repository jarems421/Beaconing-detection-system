from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from beacon_detector.evaluation.ctu13_diagnostics import (
    Ctu13DiagnosticScenario,
    Ctu13FeatureDiagnosticResult,
    DiagnosticFeatureRecord,
    ctu13_diagnostic_group_name,
    export_ctu13_feature_diagnostic_tables,
)
from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey


class Ctu13DiagnosticTests(unittest.TestCase):
    def test_grouping_logic_identifies_synthetic_and_ctu_groups(self) -> None:
        self.assertEqual(
            ctu13_diagnostic_group_name(
                _feature("beacon", "fixed_periodic"),
                source_family="synthetic",
            ),
            "synthetic_beacon",
        )
        self.assertEqual(
            ctu13_diagnostic_group_name(
                _feature("benign", "normal_keepalive"),
                source_family="synthetic",
            ),
            "synthetic_benign",
        )
        self.assertEqual(
            ctu13_diagnostic_group_name(
                _feature("beacon", "ctu13_scenario_5:ctu13_from_botnet"),
                source_family="ctu",
            ),
            "ctu_from_botnet",
        )
        self.assertEqual(
            ctu13_diagnostic_group_name(
                _feature("benign", "ctu13_scenario_5:ctu13_background"),
                source_family="ctu",
            ),
            "ctu_background",
        )

    def test_diagnostic_export_writes_expected_summary_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = Ctu13FeatureDiagnosticResult(
                records=(
                    DiagnosticFeatureRecord(
                        "synthetic_benign",
                        "synthetic",
                        None,
                        _feature("benign", "normal_keepalive", event_count=8),
                    ),
                    DiagnosticFeatureRecord(
                        "synthetic_beacon",
                        "synthetic",
                        None,
                        _feature("beacon", "fixed_periodic", event_count=12),
                    ),
                    DiagnosticFeatureRecord(
                        "ctu_from_normal",
                        "ctu",
                        "ctu13_scenario_test",
                        _feature(
                            "benign",
                            "ctu13_scenario_test:ctu13_from_normal",
                            event_count=2,
                        ),
                    ),
                    DiagnosticFeatureRecord(
                        "ctu_background",
                        "ctu",
                        "ctu13_scenario_test",
                        _feature(
                            "benign",
                            "ctu13_scenario_test:ctu13_background",
                            event_count=1,
                        ),
                    ),
                    DiagnosticFeatureRecord(
                        "ctu_from_botnet",
                        "ctu",
                        "ctu13_scenario_test",
                        _feature(
                            "beacon",
                            "ctu13_scenario_test:ctu13_from_botnet",
                            event_count=6,
                        ),
                    ),
                ),
                scenarios=(
                    Ctu13DiagnosticScenario(
                        "ctu13_scenario_test",
                        Path("sample.binetflow"),
                    ),
                ),
                synthetic_seeds=(700,),
                output_dir=Path(temp_dir),
            )

            written_paths = export_ctu13_feature_diagnostic_tables(result)
            written_names = {path.name for path in written_paths}

            self.assertIn("ctu_feature_distribution_summary.csv", written_names)
            self.assertIn("ctu_feature_shift_ranking.csv", written_names)
            self.assertIn("ctu_protocol_port_summary.csv", written_names)
            self.assertIn("ctu_diagnostic_metadata.json", written_names)

            shift_text = (Path(temp_dir) / "ctu_feature_shift_ranking.csv").read_text(
                encoding="utf-8"
            )
            self.assertIn("synthetic_benign_vs_ctu_from_normal", shift_text)


def _feature(
    label: str,
    scenario_name: str,
    *,
    event_count: int = 5,
) -> FlowFeatures:
    return FlowFeatures(
        flow_key=FlowKey("10.0.0.1", "10.0.0.2", 80, "tcp"),
        label=label,  # type: ignore[arg-type]
        scenario_name=scenario_name,
        event_count=event_count,
        total_bytes=event_count * 100,
        flow_duration_seconds=float(event_count * 10),
        size_cv=0.1,
        normalized_size_range=0.2,
        size_bin_count=2,
        dominant_size_bin_fraction=0.8,
        interarrival_iqr_seconds=1.0,
        interarrival_mad_seconds=0.5,
        gap_range_median_ratio=0.2,
        near_median_interarrival_fraction=0.75,
        interarrival_within_20pct_median_fraction=0.75,
        dominant_interval_bin_fraction=0.8,
    )


if __name__ == "__main__":
    unittest.main()
