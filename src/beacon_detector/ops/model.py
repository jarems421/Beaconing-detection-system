from __future__ import annotations

import json
import pickle
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beacon_detector.detection.supervised import (
    SupervisedDetectorConfig,
    SupervisedDetectorModel,
    fit_supervised_detector,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import Flow

from .grouping import build_operational_flows
from .schema import OperationalEvent, load_labelled_normalized_csv

OPS_MODEL_SCHEMA_VERSION = 1
OPS_MODEL_FILE = "model.pkl"
OPS_MODEL_METADATA_FILE = "metadata.json"
OPS_MODEL_TRAINING_SUMMARY_FILE = "training_summary.json"
OPS_MODEL_TRAINING_REPORT_FILE = "training_report.md"
DEFAULT_OPERATIONAL_RF_THRESHOLD = 0.65


@dataclass(frozen=True, slots=True)
class OpsModelTrainingResult:
    model_dir: Path
    model_file: Path
    metadata_json: Path
    training_summary_json: Path
    training_report_md: Path


@dataclass(frozen=True, slots=True)
class OpsModelArtifact:
    model: SupervisedDetectorModel
    metadata: dict[str, Any]


def train_random_forest_model(
    *,
    train_paths: list[str | Path],
    output_dir: str | Path,
    label_column: str = "label",
    config: SupervisedDetectorConfig | None = None,
) -> OpsModelTrainingResult:
    if not train_paths:
        raise ValueError("At least one labelled normalized CSV is required.")

    model_dir = Path(output_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    loaded_events: list[OperationalEvent] = []
    for path in train_paths:
        loaded_events.extend(
            load_labelled_normalized_csv(path, label_column=label_column)
        )
    training_events = [
        event for event in loaded_events if event.label in {"benign", "beacon"}
    ]
    skipped_unknown_count = len(loaded_events) - len(training_events)
    if not training_events:
        raise ValueError("No benign or beacon training rows were found.")

    flows, feature_rows = _training_features(training_events)
    config = config or replace(
        SupervisedDetectorConfig(),
        prediction_threshold=DEFAULT_OPERATIONAL_RF_THRESHOLD,
    )
    model = fit_supervised_detector(
        feature_rows,
        detector_type="random_forest",
        config=config,
    )

    model_file = model_dir / OPS_MODEL_FILE
    metadata_json = model_dir / OPS_MODEL_METADATA_FILE
    training_summary_json = model_dir / OPS_MODEL_TRAINING_SUMMARY_FILE
    training_report_md = model_dir / OPS_MODEL_TRAINING_REPORT_FILE

    model_file.write_bytes(pickle.dumps(model))
    metadata = _metadata(
        model=model,
        train_paths=[Path(path) for path in train_paths],
        label_column=label_column,
        loaded_event_count=len(loaded_events),
        training_event_count=len(training_events),
        skipped_unknown_event_count=skipped_unknown_count,
        flow_count=len(flows),
        feature_rows=feature_rows,
    )
    metadata_json.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    training_summary_json.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    training_report_md.write_text(_training_report(metadata), encoding="utf-8")

    return OpsModelTrainingResult(
        model_dir=model_dir,
        model_file=model_file,
        metadata_json=metadata_json,
        training_summary_json=training_summary_json,
        training_report_md=training_report_md,
    )


def load_ops_model_artifact(path: str | Path) -> OpsModelArtifact:
    artifact_path = Path(path)
    model_dir = artifact_path if artifact_path.is_dir() else artifact_path.parent
    model_file = artifact_path if artifact_path.is_file() else model_dir / OPS_MODEL_FILE
    metadata_file = model_dir / OPS_MODEL_METADATA_FILE
    if not model_file.exists():
        raise ValueError(f"Model artifact is missing {OPS_MODEL_FILE}: {model_file}")
    if not metadata_file.exists():
        raise ValueError(
            f"Model artifact is missing {OPS_MODEL_METADATA_FILE}: {metadata_file}"
        )

    model = pickle.loads(model_file.read_bytes())
    if not isinstance(model, SupervisedDetectorModel):
        raise ValueError("Model artifact does not contain a supervised detector model.")
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    if metadata.get("schema_version") != OPS_MODEL_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported operational model schema version: "
            f"{metadata.get('schema_version')}"
        )
    if tuple(metadata.get("feature_names", ())) != model.config.feature_names:
        raise ValueError("Model metadata feature names do not match the saved model.")
    return OpsModelArtifact(model=model, metadata=metadata)


def _training_features(
    events: list[OperationalEvent],
) -> tuple[list[Flow], list[FlowFeatures]]:
    flows, _ = build_operational_flows(events, label_policy="event")
    mixed_flows = [flow for flow in flows if flow.has_mixed_labels]
    if mixed_flows:
        examples = ", ".join(_flow_key_text(flow) for flow in mixed_flows[:3])
        raise ValueError(
            "Training data produced mixed-label grouped flows. "
            "Fix labels or split the input before training. "
            f"Examples: {examples}"
        )
    return flows, extract_features_from_flows(flows)


def _metadata(
    *,
    model: SupervisedDetectorModel,
    train_paths: list[Path],
    label_column: str,
    loaded_event_count: int,
    training_event_count: int,
    skipped_unknown_event_count: int,
    flow_count: int,
    feature_rows: list[FlowFeatures],
) -> dict[str, Any]:
    return {
        "schema_version": OPS_MODEL_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "detector_name": model.detector_name,
        "detector_type": model.detector_type,
        "model_file": OPS_MODEL_FILE,
        "source_files": [str(path) for path in train_paths],
        "input_contract": "normalized_csv_with_label",
        "label_column": label_column,
        "accepted_labels": ["benign", "beacon"],
        "skipped_labels": ["unknown"],
        "flow_grouping_key": [
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "direction",
        ],
        "src_port_policy": "captured_but_not_grouped",
        "loaded_event_count": loaded_event_count,
        "training_event_count": training_event_count,
        "skipped_unknown_event_count": skipped_unknown_event_count,
        "training_flow_count": flow_count,
        "beacon_training_flow_count": model.beacon_training_flow_count,
        "benign_training_flow_count": model.benign_training_flow_count,
        "feature_names": list(model.config.feature_names),
        "config": asdict(model.config),
        "validation_strategy": "not_run_in_initial_artifact_slice",
        "training_groups": [_flow_key_text(row) for row in feature_rows],
    }


def _training_report(metadata: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Operational Model Training Report",
            "",
            f"- Detector: `{metadata['detector_name']}`",
            f"- Input contract: `{metadata['input_contract']}`",
            f"- Label column: `{metadata['label_column']}`",
            f"- Loaded events: {metadata['loaded_event_count']}",
            f"- Training events: {metadata['training_event_count']}",
            f"- Skipped unknown events: {metadata['skipped_unknown_event_count']}",
            f"- Training flows: {metadata['training_flow_count']}",
            f"- Beacon flows: {metadata['beacon_training_flow_count']}",
            f"- Benign flows: {metadata['benign_training_flow_count']}",
            f"- Prediction threshold: {metadata['config']['prediction_threshold']}",
            "",
            "This model was trained from normalized labelled CSV rows. Dataset-specific",
            "sources should be adapted into that schema before training.",
            "",
        ]
    )


def _flow_key_text(row: Flow | FlowFeatures) -> str:
    key = row.flow_key
    return (
        f"{key.src_ip}|{key.direction or ''}|"
        f"{key.dst_ip}:{key.dst_port}/{key.protocol}"
    )
