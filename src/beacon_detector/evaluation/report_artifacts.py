"""Build report-ready tables and figures from existing experiment exports."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TABLES_ROOT = Path("results/tables")
DEFAULT_FIGURES_ROOT = Path("results/figures")
REPORT_READY_DIR_NAME = "report_ready"
FINAL_STORY_TABLE_DIR_NAME = "final_story"
FINAL_STORY_FIGURE_DIR_NAME = "final_story"
FINAL_HEADLINE_COLUMNS = [
    "story_stage",
    "detector_label",
    "detector_name",
    "operating_point",
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "source_file",
    "source_experiment",
    "generated_at",
]
FINAL_MINIMUM_EVIDENCE_COLUMNS = [
    "scenario_family",
    "detector_label",
    "operating_point",
    "reliability_target",
    "first_reliable_event_count",
    "interpretation",
    "source_file",
    "generated_at",
]
FINAL_CTU_THREE_STAGE_COLUMNS = [
    "story_stage",
    "label_policy",
    "detector_label",
    "feature_path",
    "compatibility_status",
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "source_file",
    "generated_at",
]
FINAL_CTU_STORY_STAGES = [
    "Synthetic direct transfer to CTU",
    "CTU-native unsupervised evaluation",
    "Within-CTU supervised evaluation",
]
FINAL_CTU_SUPERVISED_COLUMNS = [
    "label_policy",
    "detector_label",
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "tp",
    "fp",
    "tn",
    "fn",
    "interpretation",
    "source_file",
    "generated_at",
]
FINAL_FINDINGS_COLUMNS = [
    "finding_order",
    "story_stage",
    "finding",
    "evidence_artifact",
    "interpretation",
]
ARTIFACT_MANIFEST_COLUMNS = [
    "artifact_path",
    "artifact_type",
    "artifact_role",
    "story_stage",
    "source_file",
    "source_experiment",
    "generated_at",
    "label_policy",
]


def build_report_artifacts(
    tables_root: str | Path = DEFAULT_TABLES_ROOT,
    figures_root: str | Path = DEFAULT_FIGURES_ROOT,
) -> list[Path]:
    """Create concise report-ready CSV tables and static PNG figures.

    The artifacts are derived from already-exported experiment results. This function does not
    rerun detectors or change modelling logic.
    """

    tables_root = Path(tables_root)
    figures_root = Path(figures_root)
    report_ready_dir = tables_root / REPORT_READY_DIR_NAME
    report_ready_dir.mkdir(parents=True, exist_ok=True)
    figures_root.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()

    written_paths = [
        _write_detector_comparison_table(tables_root, report_ready_dir, generated_at),
        _write_minimum_evidence_threshold_table(tables_root, report_ready_dir, generated_at),
        _write_shortcut_stress_summary_table(tables_root, report_ready_dir, generated_at),
        _write_heldout_validation_summary_table(tables_root, report_ready_dir, generated_at),
        _write_ctu_transfer_summary_table(tables_root, report_ready_dir, generated_at),
        _write_ctu_native_feature_path_table(tables_root, report_ready_dir, generated_at),
        _write_ctu_supervised_summary_table(tables_root, report_ready_dir, generated_at),
        _write_final_project_findings_table(report_ready_dir, generated_at),
        _write_synthetic_detector_comparison(tables_root, figures_root),
        _write_minimum_evidence_detection_curve(tables_root, figures_root),
        _write_rf_time_size_probability_curve(tables_root, figures_root),
        _write_benign_false_positive_by_profile(tables_root, figures_root),
        _write_shortcut_stress_detector_comparison(tables_root, figures_root),
        _write_ctu_transfer_vs_native_comparison(tables_root, figures_root),
        _write_ctu_supervised_per_scenario_performance(tables_root, figures_root),
        _write_ctu_native_rf_feature_importances(tables_root, figures_root),
    ]
    written_paths.extend(
        build_final_story_artifacts(
            tables_root=tables_root,
            figures_root=figures_root,
            generated_at=generated_at,
        )
    )
    return [path for path in written_paths if path is not None]


def _write_detector_comparison_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "supervised_ml" / "baseline_comparison.csv"
    rows = []
    for row in _read_csv(source_path):
        rows.append(
            {
                "detector_name": row.get("detector_name", ""),
                "operating_point": row.get("operating_point", ""),
                "feature_set": "",
                "evaluation_scope": "standard_hardened_grid",
                "mean_precision": row.get("mean_precision", ""),
                "mean_recall": row.get("mean_recall", ""),
                "mean_f1": row.get("mean_f1", ""),
                "mean_false_positive_rate": row.get("mean_false_positive_rate", ""),
                "combined_tp": row.get("combined_tp", ""),
                "combined_fp": row.get("combined_fp", ""),
                "combined_tn": row.get("combined_tn", ""),
                "combined_fn": row.get("combined_fn", ""),
                **_provenance_columns(
                    source_experiment="supervised_ml_hardened_grid",
                    source_file=source_path,
                    generated_at=generated_at,
                    metadata=_read_metadata(source_path.parent),
                ),
            }
        )

    threshold_source = (
        tables_root / "supervised_threshold_sweep" / ("supervised_threshold_sweep_summary.csv")
    )
    key_rf_points = {
        ("full", "0.3"),
        ("full", "0.6"),
        ("timing_size", "0.4"),
    }
    metadata = _read_metadata(threshold_source.parent)
    for row in _read_csv(threshold_source):
        key = (row.get("feature_set", ""), row.get("threshold", ""))
        if key not in key_rf_points:
            continue
        rows.append(
            {
                "detector_name": "random_forest_v1",
                "operating_point": (
                    f"threshold={row.get('threshold', '')};features={row.get('feature_set', '')}"
                ),
                "feature_set": row.get("feature_set", ""),
                "evaluation_scope": row.get("evaluation_scope", "standard_hardened_grid"),
                "mean_precision": row.get("precision", ""),
                "mean_recall": row.get("recall", ""),
                "mean_f1": row.get("f1", ""),
                "mean_false_positive_rate": row.get("false_positive_rate", ""),
                "combined_tp": row.get("tp", ""),
                "combined_fp": row.get("fp", ""),
                "combined_tn": row.get("tn", ""),
                "combined_fn": row.get("fn", ""),
                **_provenance_columns(
                    source_experiment="supervised_threshold_sweep",
                    source_file=threshold_source,
                    generated_at=generated_at,
                    metadata=metadata,
                ),
            }
        )

    output_path = report_ready_dir / "detector_comparison_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_minimum_evidence_threshold_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "minimum_evidence" / "minimum_evidence_thresholds.csv"
    metadata = _read_metadata(source_path.parent)
    rows = [
        {
            **row,
            **_provenance_columns(
                source_experiment="minimum_evidence",
                source_file=source_path,
                generated_at=generated_at,
                metadata=metadata,
            ),
        }
        for row in _read_csv(source_path)
    ]

    output_path = report_ready_dir / "minimum_evidence_threshold_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_shortcut_stress_summary_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "shortcut_stress" / "shortcut_stress_summary.csv"
    metadata = _read_metadata(source_path.parent)
    rows = [
        {
            **row,
            **_provenance_columns(
                source_experiment="shortcut_stress",
                source_file=source_path,
                generated_at=generated_at,
                metadata=metadata,
            ),
        }
        for row in _read_csv(source_path)
    ]

    output_path = report_ready_dir / "shortcut_stress_summary_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_heldout_validation_summary_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    rows = []

    source_path = tables_root / "supervised_holdout" / "holdout_detector_metrics.csv"
    metadata = _read_metadata(source_path.parent)
    for row in _read_csv(source_path):
        rows.append(
            {
                "detector_name": row.get("detector", ""),
                "operating_point": "",
                "feature_set": "",
                "holdout_experiment": row.get("experiment", ""),
                "precision": row.get("precision", ""),
                "recall": row.get("recall", ""),
                "f1": row.get("f1", ""),
                "false_positive_rate": row.get("false_positive_rate", ""),
                "tp": row.get("tp", ""),
                "fp": row.get("fp", ""),
                "tn": row.get("tn", ""),
                "fn": row.get("fn", ""),
                **_provenance_columns(
                    source_experiment="supervised_holdout",
                    source_file=source_path,
                    generated_at=generated_at,
                    metadata=metadata,
                ),
            }
        )

    threshold_source = (
        tables_root
        / "supervised_threshold_sweep"
        / ("supervised_threshold_sweep_holdout_summary.csv")
    )
    metadata = _read_metadata(threshold_source.parent)
    key_rf_points = {
        ("full", "0.3"),
        ("full", "0.6"),
        ("timing_size", "0.4"),
    }
    for row in _read_csv(threshold_source):
        key = (row.get("feature_set", ""), row.get("threshold", ""))
        if key not in key_rf_points:
            continue
        rows.append(
            {
                "detector_name": "random_forest_v1",
                "operating_point": (
                    f"threshold={row.get('threshold', '')};features={row.get('feature_set', '')}"
                ),
                "feature_set": row.get("feature_set", ""),
                "holdout_experiment": row.get("holdout_experiment", ""),
                "precision": row.get("precision", ""),
                "recall": row.get("recall", ""),
                "f1": row.get("f1", ""),
                "false_positive_rate": row.get("false_positive_rate", ""),
                "tp": row.get("tp", ""),
                "fp": row.get("fp", ""),
                "tn": row.get("tn", ""),
                "fn": row.get("fn", ""),
                **_provenance_columns(
                    source_experiment="supervised_threshold_sweep_holdout",
                    source_file=threshold_source,
                    generated_at=generated_at,
                    metadata=metadata,
                ),
            }
        )

    output_path = report_ready_dir / "heldout_validation_summary_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_ctu_transfer_summary_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "ctu13_multi" / "ctu13_multi_scenario_detector_comparison.csv"
    metadata = _read_metadata(source_path.parent)
    rows = [
        {
            **row,
            "story_stage": "Synthetic direct transfer to CTU",
            **_provenance_columns(
                source_experiment="ctu13_multi_scenario_direct_transfer",
                source_file=source_path,
                generated_at=generated_at,
                metadata=metadata,
            ),
        }
        for row in _read_csv(source_path)
    ]
    output_path = report_ready_dir / "ctu_transfer_summary_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_ctu_native_feature_path_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "ctu13_native" / "ctu_feature_path_comparison.csv"
    metadata = _read_metadata(source_path.parent)
    rows = []
    for row in _read_csv(source_path):
        feature_path = row.get("feature_path", "")
        story_stage = (
            "CTU-native unsupervised evaluation"
            if feature_path == "ctu_native"
            else "Synthetic direct transfer to CTU"
        )
        rows.append(
            {
                **row,
                "story_stage": story_stage,
                **_provenance_columns(
                    source_experiment="ctu13_native_feature_path_comparison",
                    source_file=source_path,
                    generated_at=generated_at,
                    metadata=metadata,
                ),
            }
        )
    output_path = report_ready_dir / "ctu_native_feature_path_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_ctu_supervised_summary_table(
    tables_root: Path,
    report_ready_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / "ctu13_supervised" / "ctu_supervised_detector_comparison.csv"
    metadata = _read_metadata(source_path.parent)
    rows = [
        {
            **row,
            "story_stage": row.get("story_stage", "Within-CTU supervised evaluation"),
            **_provenance_columns(
                source_experiment="ctu13_within_ctu_supervised",
                source_file=source_path,
                generated_at=generated_at,
                metadata=metadata,
            ),
        }
        for row in _read_csv(source_path)
    ]
    output_path = report_ready_dir / "ctu_supervised_summary_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_final_project_findings_table(report_ready_dir: Path, generated_at: str) -> Path:
    rows = [
        {
            "finding_id": "synthetic_rf_strong",
            "story_stage": "Synthetic benchmark evaluation",
            "finding": (
                "Random Forest is the strongest detector on the current synthetic benchmark."
            ),
            "interpretation": (
                "Synthetic benchmark performance is strong but not a deployment claim."
            ),
            "generated_at": generated_at,
        },
        {
            "finding_id": "minimum_evidence_core",
            "story_stage": "Minimum-evidence analysis",
            "finding": (
                "Easy beaconing regimes can be detected with little flow history, "
                "while evasive time+size jittered flows require substantially more events."
            ),
            "interpretation": (
                "Available flow history is a core constraint for behavioural beacon detection."
            ),
            "generated_at": generated_at,
        },
        {
            "finding_id": "ctu_domain_shift",
            "story_stage": "Synthetic direct transfer to CTU",
            "finding": (
                "Direct CTU transfer exposes schema and domain shift that "
                "synthetic results alone would hide."
            ),
            "interpretation": (
                "Public-data validation must be separated from synthetic benchmark results."
            ),
            "generated_at": generated_at,
        },
        {
            "finding_id": "ctu_native_schema_aligned",
            "story_stage": "CTU-native unsupervised evaluation",
            "finding": (
                "CTU-native features are better aligned with CTU public flow "
                "fields than synthetic-style features."
            ),
            "interpretation": (
                "Native public-data modelling reduces schema mismatch but does "
                "not prove deployment readiness."
            ),
            "generated_at": generated_at,
        },
        {
            "finding_id": "not_production_soc",
            "story_stage": "Project conclusion",
            "finding": (
                "The project is a comparative flow-level detection study, "
                "not a production SOC detector."
            ),
            "interpretation": (
                "The value is the experimental pipeline, comparisons, stress tests, "
                "and documented failure analysis."
            ),
            "generated_at": generated_at,
        },
    ]
    output_path = report_ready_dir / "final_project_findings_table.csv"
    _write_csv(output_path, rows)
    return output_path


def _write_synthetic_detector_comparison(tables_root: Path, figures_root: Path) -> Path | None:
    source_path = tables_root / "report_ready" / "detector_comparison_table.csv"
    rows = [
        row
        for row in _read_csv(source_path)
        if row.get("evaluation_scope") == "standard_hardened_grid"
    ]
    if not rows:
        rows = _read_csv(tables_root / "supervised_ml" / "baseline_comparison.csv")
    if not rows:
        return None

    plt = _load_matplotlib()
    labels = [
        _short_detector_label(row.get("detector_name", ""), row.get("operating_point", ""))
        for row in rows
    ]
    values = [_to_float(row.get("mean_f1", row.get("f1", 0.0))) for row in rows]
    fig, axis = plt.subplots(figsize=(10, 4.8))
    axis.bar(range(len(labels)), values, color="#2f6f8f")
    axis.set_title("Synthetic Detector Comparison")
    axis.set_ylabel("F1 score")
    axis.set_xticks(range(len(labels)))
    axis.set_xticklabels(labels, rotation=25, ha="right")
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    output_path = figures_root / "synthetic_detector_comparison.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_minimum_evidence_detection_curve(
    tables_root: Path,
    figures_root: Path,
) -> Path | None:
    source_path = tables_root / "minimum_evidence" / "minimum_evidence_detection_curves.csv"
    rows = _read_csv(source_path)
    if not rows:
        return None

    plt = _load_matplotlib()
    scenario_order = sorted({row["scenario_family"] for row in rows})
    detector_order = _ordered_unique(row["detector_name"] for row in rows)

    fig, axes = plt.subplots(
        nrows=len(scenario_order),
        ncols=1,
        figsize=(9, max(3.0, len(scenario_order) * 2.4)),
        sharex=True,
        sharey=True,
    )
    if len(scenario_order) == 1:
        axes = [axes]

    for axis, scenario in zip(axes, scenario_order, strict=False):
        scenario_rows = [row for row in rows if row["scenario_family"] == scenario]
        for detector_name in detector_order:
            detector_rows = [row for row in scenario_rows if row["detector_name"] == detector_name]
            detector_rows.sort(key=lambda row: _to_float(row["event_count"]))
            if not detector_rows:
                continue
            axis.plot(
                [_to_float(row["event_count"]) for row in detector_rows],
                [_to_float(row["detection_rate"]) for row in detector_rows],
                marker="o",
                linewidth=1.8,
                label=_short_detector_label(detector_name, detector_rows[0]["operating_point"]),
            )
        axis.axhline(0.8, color="#888888", linestyle="--", linewidth=1.0)
        axis.set_title(scenario.replace("_", " "))
        axis.set_ylabel("Detection rate")
        axis.grid(alpha=0.25)

    axes[-1].set_xlabel("Events available in flow")
    handles, labels = axes[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, labels, loc="upper center", ncols=min(4, len(handles)))
    fig.suptitle("Minimum Evidence Detection Curves", y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.96))

    output_path = figures_root / "minimum_evidence_detection_curve.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_rf_time_size_probability_curve(
    tables_root: Path,
    figures_root: Path,
) -> Path | None:
    source_path = tables_root / "rf_signal_study" / "rf_time_size_signal_study_summary.csv"
    rows = [row for row in _read_csv(source_path) if row.get("factor_name") == "event_count"]
    if not rows:
        return None

    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(8, 4.8))
    for detector_name in _ordered_unique(row["detector_name"] for row in rows):
        detector_rows = [row for row in rows if row["detector_name"] == detector_name]
        detector_rows.sort(key=lambda row: _to_float(row["factor_value"]))
        axis.plot(
            [_to_float(row["factor_value"]) for row in detector_rows],
            [_to_float(row["mean_probability"]) for row in detector_rows],
            marker="o",
            linewidth=2,
            label=f"{row_label(detector_rows[0])}",
        )

    axis.set_title("RF Time+Size Jittered Probability by Event Count")
    axis.set_xlabel("time_size_jittered event count")
    axis.set_ylabel("Mean RF beacon probability")
    axis.set_ylim(bottom=0)
    axis.grid(alpha=0.25)
    axis.legend()
    fig.tight_layout()

    output_path = figures_root / "rf_time_size_probability_curve.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_benign_false_positive_by_profile(
    tables_root: Path,
    figures_root: Path,
) -> Path | None:
    source_path = tables_root / "shortcut_stress" / "shortcut_stress_profile_rates.csv"
    rows = [
        row
        for row in _read_csv(source_path)
        if row.get("category") == "benign_profile" and row.get("rate_type") == "false_flag_rate"
    ]
    if not rows:
        return None

    detector_names = _ordered_unique(row["detector_name"] for row in rows)
    profile_names = sorted({row["scenario_or_profile_name"] for row in rows})
    values_by_detector: dict[str, dict[str, float]] = defaultdict(dict)
    for row in rows:
        values_by_detector[row["detector_name"]][row["scenario_or_profile_name"]] = _to_float(
            row["rate"]
        )

    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(11, 5.5))
    x_positions = list(range(len(profile_names)))
    bar_width = 0.8 / max(1, len(detector_names))

    for detector_index, detector_name in enumerate(detector_names):
        offset = (detector_index - (len(detector_names) - 1) / 2) * bar_width
        axis.bar(
            [x_position + offset for x_position in x_positions],
            [
                values_by_detector[detector_name].get(profile_name, 0.0)
                for profile_name in profile_names
            ],
            width=bar_width,
            label=_short_detector_label(detector_name, ""),
        )

    axis.set_title("Benign False-Positive Rate by Profile on Shortcut Stress Suite")
    axis.set_xlabel("Benign profile")
    axis.set_ylabel("False-positive rate")
    axis.set_xticks(x_positions)
    axis.set_xticklabels([name.replace("normal_", "").replace("_", " ") for name in profile_names])
    axis.tick_params(axis="x", rotation=25)
    axis.grid(axis="y", alpha=0.25)
    axis.legend(ncols=2)
    fig.tight_layout()

    output_path = figures_root / "benign_false_positive_by_profile.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_shortcut_stress_detector_comparison(
    tables_root: Path, figures_root: Path
) -> Path | None:
    source_path = tables_root / "shortcut_stress" / "shortcut_stress_summary.csv"
    rows = _read_csv(source_path)
    if not rows:
        return None
    labels = [
        _short_detector_label(row.get("detector_name", ""), row.get("operating_point", ""))
        for row in rows
    ]
    values = [_to_float(row.get("f1", 0.0)) for row in rows]
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(10, 4.8))
    axis.bar(range(len(labels)), values, color="#8f6a2f")
    axis.set_title("Shortcut Stress Detector Comparison")
    axis.set_ylabel("F1 score")
    axis.set_xticks(range(len(labels)))
    axis.set_xticklabels(labels, rotation=25, ha="right")
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    output_path = figures_root / "shortcut_stress_detector_comparison.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_ctu_transfer_vs_native_comparison(tables_root: Path, figures_root: Path) -> Path | None:
    rows = []
    for row in _read_csv(tables_root / "ctu13_native" / "ctu_feature_path_comparison.csv"):
        if row.get("policy_name") == "conservative" and row.get("f1") not in {"", None}:
            detector_label = _short_detector_label(
                row.get("detector_name", ""),
                row.get("operating_point", ""),
            )
            rows.append(
                {
                    "label": f"{row.get('feature_path', '')}\n{detector_label}",
                    "f1": _to_float(row.get("f1", 0.0)),
                }
            )
    for row in _read_csv(
        tables_root / "ctu13_supervised" / "ctu_supervised_detector_comparison.csv"
    ):
        if row.get("policy_name") == "conservative":
            detector_label = _short_detector_label(
                row.get("detector_name", ""),
                row.get("operating_point", ""),
            )
            rows.append(
                {
                    "label": f"within CTU\n{detector_label}",
                    "f1": _to_float(row.get("f1", 0.0)),
                }
            )
    if not rows:
        return None

    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(11, 5.2))
    axis.bar(range(len(rows)), [row["f1"] for row in rows], color="#3f7f4f")
    axis.set_title("CTU Transfer vs Native Evaluation Paths")
    axis.set_ylabel("F1 score")
    axis.set_xticks(range(len(rows)))
    axis.set_xticklabels([row["label"] for row in rows], rotation=25, ha="right")
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    output_path = figures_root / "ctu_transfer_vs_native_comparison.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_ctu_supervised_per_scenario_performance(
    tables_root: Path, figures_root: Path
) -> Path | None:
    source_path = tables_root / "ctu13_supervised" / "ctu_supervised_per_scenario_metrics.csv"
    rows = [
        row
        for row in _read_csv(source_path)
        if row.get("policy_name") == "conservative" and row.get("label_group") == "all"
    ]
    if not rows:
        return None
    detector_names = _ordered_unique(row["detector_name"] for row in rows)
    scenario_names = sorted({row["ctu_scenario"] for row in rows})
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(9, 4.8))
    x_positions = list(range(len(scenario_names)))
    bar_width = 0.8 / max(1, len(detector_names))
    for detector_index, detector_name in enumerate(detector_names):
        offset = (detector_index - (len(detector_names) - 1) / 2) * bar_width
        detector_rows = {
            row["ctu_scenario"]: row for row in rows if row["detector_name"] == detector_name
        }
        axis.bar(
            [position + offset for position in x_positions],
            [
                _to_float(detector_rows.get(scenario, {}).get("f1", 0.0))
                for scenario in scenario_names
            ],
            width=bar_width,
            label=_short_detector_label(detector_name, ""),
        )
    axis.set_title("Within-CTU Supervised Performance by Held-Out Scenario")
    axis.set_ylabel("F1 score")
    axis.set_xticks(x_positions)
    axis.set_xticklabels(scenario_names)
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.tight_layout()
    output_path = figures_root / "ctu_supervised_per_scenario_performance.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_ctu_native_rf_feature_importances(tables_root: Path, figures_root: Path) -> Path | None:
    source_path = tables_root / "ctu13_supervised" / "ctu_supervised_feature_importance.csv"
    rows = [
        row
        for row in _read_csv(source_path)
        if row.get("policy_name") == "conservative"
        and row.get("detector_name") == "ctu_native_random_forest_v1"
        and row.get("value_type") == "feature_importance"
    ]
    if not rows:
        return None
    values_by_feature: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        values_by_feature[row["feature_name"]].append(_to_float(row.get("absolute_value", 0.0)))
    ranked = sorted(
        ((feature, sum(values) / len(values)) for feature, values in values_by_feature.items()),
        key=lambda item: item[1],
        reverse=True,
    )[:10]
    if not ranked:
        return None
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(9, 5.2))
    labels = [item[0] for item in ranked][::-1]
    values = [item[1] for item in ranked][::-1]
    axis.barh(range(len(labels)), values, color="#6c5f9f")
    axis.set_title("CTU-Native RF Feature Importances")
    axis.set_xlabel("Mean importance across folds")
    axis.set_yticks(range(len(labels)))
    axis.set_yticklabels(labels)
    axis.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    output_path = figures_root / "ctu_native_rf_feature_importances.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def build_final_story_artifacts(
    *,
    tables_root: Path,
    figures_root: Path,
    generated_at: str,
) -> list[Path]:
    """Create curated presentation artifacts from existing exported tables only."""

    final_table_dir = tables_root / FINAL_STORY_TABLE_DIR_NAME
    final_figure_dir = figures_root / FINAL_STORY_FIGURE_DIR_NAME
    final_table_dir.mkdir(parents=True, exist_ok=True)
    final_figure_dir.mkdir(parents=True, exist_ok=True)

    written_paths: list[Path | None] = [
        _write_final_headline_detector_comparison(tables_root, final_table_dir, generated_at),
        _write_final_minimum_evidence_story_table(tables_root, final_table_dir, generated_at),
        _write_final_ctu_three_stage_comparison(tables_root, final_table_dir, generated_at),
        _write_final_ctu_supervised_tradeoff_table(tables_root, final_table_dir, generated_at),
        _write_final_findings_table(final_table_dir),
        _write_final_synthetic_detector_figure(final_table_dir, final_figure_dir),
        _write_final_minimum_evidence_figure(final_table_dir, final_figure_dir),
        _write_final_ctu_three_stage_figure(final_table_dir, final_figure_dir),
        _write_final_ctu_supervised_scenario_figure(tables_root, final_figure_dir),
        _write_final_research_story_summary_figure(final_figure_dir),
    ]
    concrete_paths = [path for path in written_paths if path is not None]
    concrete_paths.append(
        _write_artifact_manifest(
            tables_root=tables_root,
            figures_root=figures_root,
            final_table_dir=final_table_dir,
            final_figure_dir=final_figure_dir,
            generated_at=generated_at,
            headline_paths=concrete_paths,
        )
    )
    return concrete_paths


def _write_final_headline_detector_comparison(
    tables_root: Path,
    final_table_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / REPORT_READY_DIR_NAME / "detector_comparison_table.csv"
    rows: list[dict[str, Any]] = []
    for row in _read_csv(source_path):
        precision = row.get("mean_precision", row.get("precision", ""))
        recall = row.get("mean_recall", row.get("recall", ""))
        f1 = row.get("mean_f1", row.get("f1", ""))
        fpr = row.get("mean_false_positive_rate", row.get("false_positive_rate", ""))
        rows.append(
            {
                "story_stage": "Synthetic benchmark evaluation",
                "detector_label": _final_detector_label(
                    row.get("detector_name", ""), row.get("operating_point", "")
                ),
                "detector_name": row.get("detector_name", ""),
                "operating_point": row.get("operating_point", ""),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "false_positive_rate": fpr,
                "source_file": source_path.as_posix(),
                "source_experiment": row.get("source_experiment", "report_ready"),
                "generated_at": generated_at,
            }
        )
    output_path = final_table_dir / "headline_detector_comparison.csv"
    _write_csv(output_path, rows, fieldnames=FINAL_HEADLINE_COLUMNS)
    return output_path


def _write_final_minimum_evidence_story_table(
    tables_root: Path,
    final_table_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / REPORT_READY_DIR_NAME / "minimum_evidence_threshold_table.csv"
    rows: list[dict[str, Any]] = []
    for row in _read_csv(source_path):
        if row.get("reliability_target") != "0.8":
            continue
        scenario = row.get("scenario_family", "")
        first_count = row.get("first_reliable_event_count", "")
        rows.append(
            {
                "scenario_family": scenario,
                "detector_label": _final_detector_label(
                    row.get("detector_name", ""), row.get("operating_point", "")
                ),
                "operating_point": row.get("operating_point", ""),
                "reliability_target": row.get("reliability_target", ""),
                "first_reliable_event_count": first_count,
                "interpretation": _minimum_evidence_interpretation(scenario, first_count),
                "source_file": source_path.as_posix(),
                "generated_at": generated_at,
            }
        )
    output_path = final_table_dir / "minimum_evidence_story_table.csv"
    _write_csv(output_path, rows, fieldnames=FINAL_MINIMUM_EVIDENCE_COLUMNS)
    return output_path


def _write_final_ctu_three_stage_comparison(
    tables_root: Path,
    final_table_dir: Path,
    generated_at: str,
) -> Path:
    rows: list[dict[str, Any]] = []
    transfer_source = tables_root / REPORT_READY_DIR_NAME / "ctu_transfer_summary_table.csv"
    for row in _read_csv(transfer_source):
        if row.get("policy_name") != "conservative":
            continue
        detector_name = row.get("detector_name", "")
        if detector_name not in {
            "rule_baseline_v2_hardened_final",
            "local_outlier_factor_v1",
            "rf_full_threshold_0p6",
            "rf_full_threshold_0p3",
        }:
            continue
        rows.append(
            _ctu_story_row(
                row=row,
                story_stage="Synthetic direct transfer to CTU",
                feature_path="transferred_flowfeatures",
                compatibility_status="compatible_existing_transfer_path",
                source_path=transfer_source,
                generated_at=generated_at,
            )
        )

    native_source = tables_root / REPORT_READY_DIR_NAME / "ctu_native_feature_path_table.csv"
    for row in _read_csv(native_source):
        if (
            row.get("policy_name") == "conservative"
            and row.get("feature_path") == "ctu_native"
            and row.get("detector_name") == "local_outlier_factor_v1"
        ):
            rows.append(
                _ctu_story_row(
                    row=row,
                    story_stage="CTU-native unsupervised evaluation",
                    feature_path="ctu_native",
                    compatibility_status=row.get("compatibility_status", ""),
                    source_path=native_source,
                    generated_at=generated_at,
                )
            )

    supervised_source = tables_root / REPORT_READY_DIR_NAME / "ctu_supervised_summary_table.csv"
    for row in _read_csv(supervised_source):
        if row.get("policy_name") == "conservative":
            rows.append(
                _ctu_story_row(
                    row=row,
                    story_stage="Within-CTU supervised evaluation",
                    feature_path="ctu_native",
                    compatibility_status="compatible_ctu_native_training",
                    source_path=supervised_source,
                    generated_at=generated_at,
                )
            )
    rows.extend(_missing_ctu_stage_rows(rows, generated_at))
    output_path = final_table_dir / "ctu_three_stage_comparison.csv"
    _write_csv(output_path, rows, fieldnames=FINAL_CTU_THREE_STAGE_COLUMNS)
    return output_path


def _ctu_story_row(
    *,
    row: dict[str, str],
    story_stage: str,
    feature_path: str,
    compatibility_status: str,
    source_path: Path,
    generated_at: str,
) -> dict[str, Any]:
    return {
        "story_stage": story_stage,
        "label_policy": row.get("policy_name", "conservative"),
        "detector_label": _final_detector_label(
            row.get("detector_name", ""), row.get("operating_point", "")
        ),
        "feature_path": feature_path,
        "compatibility_status": compatibility_status,
        "precision": row.get("precision", ""),
        "recall": row.get("recall", ""),
        "f1": row.get("f1", ""),
        "false_positive_rate": row.get("false_positive_rate", ""),
        "source_file": source_path.as_posix(),
        "generated_at": generated_at,
    }


def _missing_ctu_stage_rows(
    rows: list[dict[str, Any]],
    generated_at: str,
) -> list[dict[str, Any]]:
    present_stages = {row.get("story_stage", "") for row in rows}
    return [
        {
            "story_stage": stage,
            "label_policy": "conservative",
            "detector_label": "",
            "feature_path": "",
            "compatibility_status": "source_missing",
            "precision": "",
            "recall": "",
            "f1": "",
            "false_positive_rate": "",
            "source_file": "",
            "generated_at": generated_at,
        }
        for stage in FINAL_CTU_STORY_STAGES
        if stage not in present_stages
    ]


def _write_final_ctu_supervised_tradeoff_table(
    tables_root: Path,
    final_table_dir: Path,
    generated_at: str,
) -> Path:
    source_path = tables_root / REPORT_READY_DIR_NAME / "ctu_supervised_summary_table.csv"
    rows: list[dict[str, Any]] = []
    for row in _read_csv(source_path):
        label = _final_detector_label(row.get("detector_name", ""), row.get("operating_point", ""))
        rows.append(
            {
                "label_policy": row.get("policy_name", ""),
                "detector_label": label,
                "precision": row.get("precision", ""),
                "recall": row.get("recall", ""),
                "f1": row.get("f1", ""),
                "false_positive_rate": row.get("false_positive_rate", ""),
                "tp": row.get("tp", ""),
                "fp": row.get("fp", ""),
                "tn": row.get("tn", ""),
                "fn": row.get("fn", ""),
                "interpretation": _ctu_supervised_interpretation(label, row.get("policy_name", "")),
                "source_file": source_path.as_posix(),
                "generated_at": generated_at,
            }
        )
    output_path = final_table_dir / "ctu_supervised_tradeoff_table.csv"
    _write_csv(output_path, rows, fieldnames=FINAL_CTU_SUPERVISED_COLUMNS)
    return output_path


def _write_final_findings_table(final_table_dir: Path) -> Path:
    rows = [
        {
            "finding_order": 1,
            "story_stage": "Synthetic benchmark evaluation",
            "finding": "Synthetic RF is strongest on the controlled synthetic benchmark.",
            "evidence_artifact": "headline_detector_comparison.csv",
            "interpretation": "Flow-level behavioural features work well in controlled settings.",
        },
        {
            "finding_order": 2,
            "story_stage": "Interpretable baseline",
            "finding": "The rule baseline remains the strongest interpretable reference.",
            "evidence_artifact": "headline_detector_comparison.csv",
            "interpretation": (
                "Rules are valuable for explanation even when RF is stronger overall."
            ),
        },
        {
            "finding_order": 3,
            "story_stage": "Minimum-evidence analysis",
            "finding": "Minimum evidence is the core research result.",
            "evidence_artifact": "minimum_evidence_story_table.csv",
            "interpretation": "Detector reliability depends sharply on available flow history.",
        },
        {
            "finding_order": 4,
            "story_stage": "Hardest evasive regime",
            "finding": "Low-event high-jitter size-overlapping time_size_jittered remains hardest.",
            "evidence_artifact": "minimum_evidence_story_table.csv",
            "interpretation": "Aggregate flow features lose separability when evidence is sparse.",
        },
        {
            "finding_order": 5,
            "story_stage": "Synthetic direct transfer to CTU",
            "finding": "CTU direct transfer exposes schema and domain shift.",
            "evidence_artifact": "ctu_three_stage_comparison.csv",
            "interpretation": "Synthetic benchmark success does not imply public-data transfer.",
        },
        {
            "finding_order": 6,
            "story_stage": "CTU-native unsupervised evaluation",
            "finding": (
                "CTU-native modelling is better aligned with CTU data, "
                "but still not deployment proof."
            ),
            "evidence_artifact": "ctu_three_stage_comparison.csv",
            "interpretation": (
                "Native fields reduce schema mismatch but do not solve CTU validation."
            ),
        },
        {
            "finding_order": 7,
            "story_stage": "Project conclusion",
            "finding": "The project is a comparative study, not a production SOC detector.",
            "evidence_artifact": "docs/report_draft.md",
            "interpretation": (
                "The contribution is comparison, stress testing, and failure analysis."
            ),
        },
    ]
    output_path = final_table_dir / "final_findings_table.csv"
    _write_csv(output_path, rows, fieldnames=FINAL_FINDINGS_COLUMNS)
    return output_path


def _write_artifact_manifest(
    *,
    tables_root: Path,
    figures_root: Path,
    final_table_dir: Path,
    final_figure_dir: Path,
    generated_at: str,
    headline_paths: list[Path],
) -> Path:
    rows: list[dict[str, Any]] = []
    for path in headline_paths:
        rows.append(
            _manifest_row(
                artifact_path=path,
                artifact_role="headline",
                generated_at=generated_at,
                source_file="",
                source_experiment="final_story",
                label_policy=_label_policy_for_artifact(path),
            )
        )
    supporting_paths = [
        tables_root / REPORT_READY_DIR_NAME / "detector_comparison_table.csv",
        tables_root / REPORT_READY_DIR_NAME / "minimum_evidence_threshold_table.csv",
        tables_root / REPORT_READY_DIR_NAME / "ctu_transfer_summary_table.csv",
        tables_root / REPORT_READY_DIR_NAME / "ctu_native_feature_path_table.csv",
        tables_root / REPORT_READY_DIR_NAME / "ctu_supervised_summary_table.csv",
        tables_root / "ctu13_supervised" / "ctu_supervised_feature_importance.csv",
        figures_root / "synthetic_detector_comparison.png",
        figures_root / "minimum_evidence_detection_curve.png",
        figures_root / "ctu_transfer_vs_native_comparison.png",
    ]
    diagnostic_paths = [
        tables_root / "ctu13_supervised" / "ctu_supervised_false_positive_diagnostics.csv",
        tables_root / "ctu13_supervised" / "ctu_supervised_false_negative_diagnostics.csv",
        figures_root / "benign_false_positive_by_profile.png",
        figures_root / "rf_time_size_probability_curve.png",
        figures_root / "ctu_native_rf_feature_importances.png",
    ]
    for path in supporting_paths:
        if path.exists():
            rows.append(
                _manifest_row(
                    artifact_path=path,
                    artifact_role="supporting",
                    generated_at=generated_at,
                    source_file="",
                    source_experiment="existing_export",
                    label_policy=_label_policy_for_artifact(path),
                )
            )
    for path in diagnostic_paths:
        if path.exists():
            rows.append(
                _manifest_row(
                    artifact_path=path,
                    artifact_role="diagnostic",
                    generated_at=generated_at,
                    source_file="",
                    source_experiment="existing_export",
                    label_policy=_label_policy_for_artifact(path),
                )
            )
    rows.extend(_missing_manifest_role_rows(rows, generated_at))
    output_path = final_table_dir / "artifact_manifest.csv"
    _write_csv(output_path, rows, fieldnames=ARTIFACT_MANIFEST_COLUMNS)
    return output_path


def _missing_manifest_role_rows(
    rows: list[dict[str, Any]],
    generated_at: str,
) -> list[dict[str, Any]]:
    present_roles = {row.get("artifact_role", "") for row in rows}
    missing_rows = []
    for role in ("headline", "supporting", "diagnostic"):
        if role in present_roles:
            continue
        missing_rows.append(
            {
                "artifact_path": "",
                "artifact_type": "",
                "artifact_role": role,
                "story_stage": "Supporting evidence",
                "source_file": "",
                "source_experiment": "expected_artifact_missing",
                "generated_at": generated_at,
                "label_policy": "not_applicable",
            }
        )
    return missing_rows


def _manifest_row(
    *,
    artifact_path: Path,
    artifact_role: str,
    generated_at: str,
    source_file: str,
    source_experiment: str,
    label_policy: str,
) -> dict[str, Any]:
    return {
        "artifact_path": artifact_path.as_posix(),
        "artifact_type": artifact_path.suffix.lstrip(".") or "directory",
        "artifact_role": artifact_role,
        "story_stage": _story_stage_for_artifact(artifact_path),
        "source_file": source_file,
        "source_experiment": source_experiment,
        "generated_at": generated_at,
        "label_policy": label_policy,
    }


def _write_final_synthetic_detector_figure(
    final_table_dir: Path,
    final_figure_dir: Path,
) -> Path | None:
    rows = _read_csv(final_table_dir / "headline_detector_comparison.csv")
    if not rows:
        return None
    metrics = ["precision", "recall", "f1", "false_positive_rate"]
    labels = [row["detector_label"] for row in rows]
    plt = _load_matplotlib()
    fig, axes = plt.subplots(2, 2, figsize=(12, 7), sharex=True)
    for axis, metric in zip(axes.flatten(), metrics, strict=False):
        axis.bar(range(len(rows)), [_to_float(row[metric]) for row in rows], color="#2f6f8f")
        axis.set_title(_metric_label(metric))
        axis.set_ylim(bottom=0)
        axis.grid(axis="y", alpha=0.25)
        axis.set_xticks(range(len(rows)))
        axis.set_xticklabels(labels, rotation=25, ha="right")
    fig.suptitle("Synthetic Benchmark Detector Comparison")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    output_path = final_figure_dir / "01_synthetic_detector_comparison.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_final_minimum_evidence_figure(
    final_table_dir: Path,
    final_figure_dir: Path,
) -> Path | None:
    rows = _read_csv(final_table_dir / "minimum_evidence_story_table.csv")
    rows = [
        row for row in rows if row.get("detector_label") in {"Rule", "LOF", "RF @ 0.3", "RF @ 0.6"}
    ]
    if not rows:
        return None
    scenario_order = [
        "fixed_periodic",
        "jittered",
        "bursty",
        "time_size_jittered",
        "hard_time_size_jittered_overlap",
    ]
    detector_order = _ordered_unique(row["detector_label"] for row in rows)
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(12, 5.6))
    x_positions = list(range(len(scenario_order)))
    bar_width = 0.8 / max(1, len(detector_order))
    for detector_index, detector_label in enumerate(detector_order):
        offset = (detector_index - (len(detector_order) - 1) / 2) * bar_width
        detector_rows = {
            row["scenario_family"]: row for row in rows if row["detector_label"] == detector_label
        }
        axis.bar(
            [position + offset for position in x_positions],
            [
                _to_float(detector_rows.get(scenario, {}).get("first_reliable_event_count", 0))
                for scenario in scenario_order
            ],
            width=bar_width,
            label=detector_label,
        )
    axis.set_title("Minimum Evidence Needed for >= 0.8 Detection")
    axis.set_ylabel("First reliable event count")
    axis.set_xticks(x_positions)
    axis.set_xticklabels(
        [scenario.replace("_", " ") for scenario in scenario_order], rotation=20, ha="right"
    )
    axis.grid(axis="y", alpha=0.25)
    axis.legend(ncols=2)
    fig.tight_layout()
    output_path = final_figure_dir / "02_minimum_evidence_core_result.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_final_ctu_three_stage_figure(
    final_table_dir: Path,
    final_figure_dir: Path,
) -> Path | None:
    rows = _read_csv(final_table_dir / "ctu_three_stage_comparison.csv")
    rows = [row for row in rows if row.get("precision") not in {"", None}]
    if not rows:
        return None
    metrics = ["precision", "recall", "f1", "false_positive_rate"]
    labels = [f"{row['story_stage']}\n{row['detector_label']}" for row in rows]
    plt = _load_matplotlib()
    fig, axes = plt.subplots(2, 2, figsize=(13, 7.5), sharex=True)
    for axis, metric in zip(axes.flatten(), metrics, strict=False):
        axis.bar(range(len(rows)), [_to_float(row[metric]) for row in rows], color="#3f7f4f")
        axis.set_title(_metric_label(metric))
        axis.set_ylim(bottom=0)
        axis.grid(axis="y", alpha=0.25)
        axis.set_xticks(range(len(rows)))
        axis.set_xticklabels(labels, rotation=25, ha="right")
    fig.suptitle("CTU-13: Three Evaluation Stories, Different Tradeoffs")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    output_path = final_figure_dir / "03_ctu_three_stage_comparison.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_final_ctu_supervised_scenario_figure(
    tables_root: Path,
    final_figure_dir: Path,
) -> Path | None:
    source_path = tables_root / "ctu13_supervised" / "ctu_supervised_per_scenario_metrics.csv"
    rows = [
        row
        for row in _read_csv(source_path)
        if row.get("policy_name") == "conservative" and row.get("label_group") == "all"
    ]
    if not rows:
        return None
    detector_labels = _ordered_unique(
        _final_detector_label(row["detector_name"], row.get("operating_point", "")) for row in rows
    )
    scenario_names = sorted({row["ctu_scenario"] for row in rows})
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(9.5, 5))
    x_positions = list(range(len(scenario_names)))
    bar_width = 0.8 / max(1, len(detector_labels))
    for detector_index, detector_label in enumerate(detector_labels):
        offset = (detector_index - (len(detector_labels) - 1) / 2) * bar_width
        detector_rows = {
            row["ctu_scenario"]: row
            for row in rows
            if _final_detector_label(row["detector_name"], row.get("operating_point", ""))
            == detector_label
        }
        axis.bar(
            [position + offset for position in x_positions],
            [
                _to_float(detector_rows.get(scenario, {}).get("f1", 0.0))
                for scenario in scenario_names
            ],
            width=bar_width,
            label=detector_label,
        )
    axis.set_title("Within-CTU Supervised Performance by Held-Out Scenario")
    axis.set_ylabel("F1 score")
    axis.set_xticks(x_positions)
    axis.set_xticklabels(scenario_names)
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.tight_layout()
    output_path = final_figure_dir / "04_ctu_supervised_per_scenario.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _write_final_research_story_summary_figure(final_figure_dir: Path) -> Path:
    plt = _load_matplotlib()
    fig, axis = plt.subplots(figsize=(13, 3.4))
    axis.axis("off")
    steps = [
        ("Synthetic\nsuccess", "RF strong on\ncontrolled flows"),
        ("Stress tests\nexpose limits", "Hard benign +\nshortcut overlap"),
        ("Minimum evidence\nfinding", "Evasive flows need\nmore history"),
        ("CTU domain\nshift", "Synthetic transfer\nfalse-positives"),
        ("CTU-native\npath", "Better aligned,\nstill limited"),
    ]
    for index, (title, subtitle) in enumerate(steps):
        x = 0.05 + index * 0.19
        axis.text(
            x,
            0.58,
            title,
            ha="center",
            va="center",
            fontsize=13,
            fontweight="bold",
            bbox={"boxstyle": "round,pad=0.55", "facecolor": "#eef4f1", "edgecolor": "#3f7f4f"},
        )
        axis.text(x, 0.22, subtitle, ha="center", va="center", fontsize=10)
        if index < len(steps) - 1:
            axis.annotate(
                "",
                xy=(x + 0.085, 0.58),
                xytext=(x + 0.14, 0.58),
                arrowprops={"arrowstyle": "<-", "color": "#555555", "lw": 1.5},
            )
    axis.set_title("Final Research Story: Flow-Level Beaconing Detection", fontsize=15, pad=15)
    fig.tight_layout()
    output_path = final_figure_dir / "05_final_research_story_summary.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def _final_detector_label(detector_name: str, operating_point: str) -> str:
    if detector_name == "rule_baseline_v2_hardened_final":
        return "Rule"
    if detector_name == "statistical_zscore_baseline_v1":
        return "Statistical"
    if detector_name == "local_outlier_factor_v1":
        return "LOF"
    if detector_name == "logistic_regression_v1":
        return "LR"
    if detector_name == "random_forest_v1":
        if "threshold=0.6" in operating_point:
            return "RF @ 0.6"
        if "threshold=0.3" in operating_point:
            return "RF @ 0.3"
        if "threshold=0.4" in operating_point:
            return "RF timing+size @ 0.4"
        return "RF"
    if detector_name == "rf_full_threshold_0p6":
        return "Synthetic RF @ 0.6"
    if detector_name == "rf_full_threshold_0p3":
        return "Synthetic RF @ 0.3"
    if detector_name == "rf_timing_size_threshold_0p4":
        return "RF timing+size @ 0.4"
    if detector_name == "ctu_native_random_forest_v1":
        return "CTU-native RF"
    if detector_name == "ctu_native_logistic_regression_v1":
        return "CTU-native LR"
    return _short_detector_label(detector_name, operating_point)


def _minimum_evidence_interpretation(scenario_family: str, event_count: str) -> str:
    if not event_count:
        return "not_reliable_in_sweep"
    if "time_size" in scenario_family:
        return "evasive_regime_more_history"
    return "easy_regime_low_history"


def _ctu_supervised_interpretation(detector_label: str, label_policy: str) -> str:
    if label_policy == "background_as_benign_sensitivity":
        return "background_sensitivity_is_not_headline_result"
    if detector_label == "CTU-native LR":
        return "higher_recall_higher_false_positive_rate"
    if detector_label == "CTU-native RF":
        return "lower_false_positive_rate_lower_recall"
    return "ctu_native_supervised_tradeoff"


def _story_stage_for_artifact(path: Path) -> str:
    name = path.name
    if "ctu" in name:
        if "supervised" in name:
            return "Within-CTU supervised evaluation"
        if "native" in name:
            return "CTU-native unsupervised evaluation"
        return "Synthetic direct transfer to CTU"
    if "minimum_evidence" in name:
        return "Minimum-evidence analysis"
    if "shortcut" in name:
        return "Shortcut stress evaluation"
    if "synthetic" in name or "detector_comparison" in name:
        return "Synthetic benchmark evaluation"
    if "final" in name or "story" in name:
        return "Project conclusion"
    return "Supporting evidence"


def _label_policy_for_artifact(path: Path) -> str:
    name = path.name
    if "ctu" in name:
        if "sensitivity" in name:
            return "conservative_and_background_as_benign_sensitivity"
        return "conservative"
    return "not_applicable"


def _metric_label(metric_name: str) -> str:
    labels = {
        "precision": "Precision",
        "recall": "Recall",
        "f1": "F1 score",
        "false_positive_rate": "False-positive rate",
    }
    return labels.get(metric_name, metric_name)


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def _write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = fieldnames or _fieldnames_from_rows(rows)
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _fieldnames_from_rows(rows: list[dict[str, Any]]) -> list[str]:
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames


def _read_metadata(folder: Path) -> dict[str, Any]:
    if not folder.exists():
        return {}
    metadata_paths = sorted(folder.glob("*metadata.json"))
    if not metadata_paths:
        return {}
    with metadata_paths[0].open("r", encoding="utf-8") as metadata_file:
        return json.load(metadata_file)


def _provenance_columns(
    source_experiment: str,
    source_file: Path,
    generated_at: str,
    metadata: dict[str, Any],
) -> dict[str, str]:
    return {
        "source_experiment": source_experiment,
        "source_file": source_file.as_posix(),
        "generated_at": generated_at,
        "source_export_timestamp_utc": str(metadata.get("export_timestamp_utc", "")),
        "feature_schema_version": str(metadata.get("feature_schema_version", "")),
    }


def _load_matplotlib() -> Any:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def _to_float(value: str | int | float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _ordered_unique(values: Any) -> list[str]:
    unique_values: list[str] = []
    for value in values:
        if value not in unique_values:
            unique_values.append(value)
    return unique_values


def _short_detector_label(detector_name: str, operating_point: str) -> str:
    label = detector_name
    label = label.replace("rule_baseline_v2_hardened_final", "Rule")
    label = label.replace("local_outlier_factor_v1", "LOF")
    label = label.replace("rf_full_threshold_0p6", "RF full @ 0.6")
    label = label.replace("rf_full_threshold_0p3", "RF full @ 0.3")
    label = label.replace("rf_timing_size_threshold_0p4", "RF timing+size @ 0.4")
    label = label.replace("ctu_native_logistic_regression_v1", "CTU LR")
    label = label.replace("ctu_native_random_forest_v1", "CTU RF")
    if label == detector_name and operating_point:
        return f"{detector_name} ({operating_point})"
    return label


def row_label(row: dict[str, str]) -> str:
    return _short_detector_label(
        row.get("detector_name", ""),
        f"threshold={row.get('threshold', '')}",
    )


if __name__ == "__main__":
    for written_path in build_report_artifacts():
        print(written_path)
