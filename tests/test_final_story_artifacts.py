from __future__ import annotations

import csv
from pathlib import Path
import unittest

from beacon_detector.evaluation.report_artifacts import build_report_artifacts


class FinalStoryArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build_report_artifacts()

    def test_final_story_tables_are_generated_with_required_columns(self) -> None:
        expected_columns = {
            "headline_detector_comparison.csv": {
                "story_stage",
                "detector_label",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
            },
            "minimum_evidence_story_table.csv": {
                "scenario_family",
                "detector_label",
                "reliability_target",
                "first_reliable_event_count",
                "interpretation",
            },
            "ctu_three_stage_comparison.csv": {
                "story_stage",
                "label_policy",
                "detector_label",
                "feature_path",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
            },
            "ctu_supervised_tradeoff_table.csv": {
                "label_policy",
                "detector_label",
                "precision",
                "recall",
                "false_positive_rate",
                "interpretation",
            },
            "final_findings_table.csv": {
                "finding_order",
                "story_stage",
                "finding",
                "evidence_artifact",
                "interpretation",
            },
        }
        for file_name, columns in expected_columns.items():
            path = Path("results/tables/final_story") / file_name
            self.assertTrue(path.exists(), file_name)
            self.assertTrue(columns.issubset(_columns(path)), file_name)

    def test_artifact_manifest_exists_and_marks_headline_outputs(self) -> None:
        path = Path("results/tables/final_story/artifact_manifest.csv")
        self.assertTrue(path.exists())
        rows = _rows(path)
        self.assertTrue(any(row["artifact_role"] == "headline" for row in rows))
        self.assertTrue(any(row["artifact_role"] == "supporting" for row in rows))
        self.assertTrue(any(row["artifact_role"] == "diagnostic" for row in rows))

    def test_ctu_story_table_preserves_three_public_data_labels(self) -> None:
        rows = _rows(Path("results/tables/final_story/ctu_three_stage_comparison.csv"))
        story_stages = {row["story_stage"] for row in rows}
        self.assertIn("Synthetic direct transfer to CTU", story_stages)
        self.assertIn("CTU-native unsupervised evaluation", story_stages)
        self.assertIn("Within-CTU supervised evaluation", story_stages)

    def test_final_findings_include_non_production_soc_limitation(self) -> None:
        text = Path("results/tables/final_story/final_findings_table.csv").read_text(
            encoding="utf-8"
        )
        self.assertIn("not a production SOC detector", text)

    def test_report_draft_contains_final_conclusion_themes(self) -> None:
        text = Path("docs/report_draft.md").read_text(encoding="utf-8")
        self.assertIn("minimum-evidence result", text)
        self.assertIn("CTU-13 validation exposes schema and domain shift", text)
        self.assertIn("not a production SOC detector", text)

    def test_final_story_figures_are_generated(self) -> None:
        expected = {
            "01_synthetic_detector_comparison.png",
            "02_minimum_evidence_core_result.png",
            "03_ctu_three_stage_comparison.png",
            "04_ctu_supervised_per_scenario.png",
            "05_final_research_story_summary.png",
        }
        figure_dir = Path("results/figures/final_story")
        actual = {path.name for path in figure_dir.glob("*.png")}
        self.assertTrue(expected.issubset(actual))


def _columns(path: Path) -> set[str]:
    with path.open(newline="", encoding="utf-8") as input_file:
        return set(csv.DictReader(input_file).fieldnames or [])


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as input_file:
        return list(csv.DictReader(input_file))


if __name__ == "__main__":
    unittest.main()
