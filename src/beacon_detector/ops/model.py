from __future__ import annotations

import json
import pickle
import platform
import sys
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from sklearn.model_selection import StratifiedGroupKFold

from beacon_detector.detection.supervised import (
    SupervisedDetectorConfig,
    SupervisedDetectorModel,
    detect_flow_feature_rows_supervised,
    fit_supervised_detector,
)
from beacon_detector.evaluation.metrics import (
    ClassificationMetrics,
    calculate_classification_metrics,
    summarize_metric_spread,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import Flow

from .grouping import build_operational_flows
from .schema import OperationalEvent, load_labelled_normalized_csv

OPS_MODEL_SCHEMA_VERSION = 1
OPS_MODEL_FILE = "model.pkl"
OPS_MODEL_METADATA_FILE = "metadata.json"
OPS_MODEL_ARTIFACT_MANIFEST_FILE = "artifact_manifest.json"
OPS_MODEL_TRAINING_SUMMARY_FILE = "training_summary.json"
OPS_MODEL_TRAINING_REPORT_FILE = "training_report.md"
DEFAULT_OPERATIONAL_RF_THRESHOLD = 0.65
DEFAULT_GROUPED_VALIDATION_FOLDS = 5
ThresholdProfileName = Literal["conservative", "balanced", "sensitive"]


@dataclass(frozen=True, slots=True)
class OpsModelTrainingResult:
    model_dir: Path
    model_file: Path
    metadata_json: Path
    artifact_manifest_json: Path
    training_summary_json: Path
    training_report_md: Path


@dataclass(frozen=True, slots=True)
class OpsModelArtifact:
    model: SupervisedDetectorModel
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class OpsGroupedValidationFold:
    fold: int
    train_flow_count: int
    validation_flow_count: int
    validation_group_count: int
    metrics: ClassificationMetrics


@dataclass(frozen=True, slots=True)
class OpsValidationPrediction:
    fold: int
    true_label: str
    score: float


@dataclass(frozen=True, slots=True)
class OpsGroupedValidationResult:
    strategy: str
    requested_folds: int
    executed_folds: int
    skipped_reason: str | None
    folds: tuple[OpsGroupedValidationFold, ...]
    predictions: tuple[OpsValidationPrediction, ...] = ()


def train_random_forest_model(
    *,
    train_paths: list[str | Path],
    output_dir: str | Path,
    label_column: str = "label",
    config: SupervisedDetectorConfig | None = None,
    validation_folds: int = DEFAULT_GROUPED_VALIDATION_FOLDS,
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
    validation = validate_grouped_random_forest(
        feature_rows,
        config=config,
        requested_folds=validation_folds,
    )

    model_file = model_dir / OPS_MODEL_FILE
    metadata_json = model_dir / OPS_MODEL_METADATA_FILE
    artifact_manifest_json = model_dir / OPS_MODEL_ARTIFACT_MANIFEST_FILE
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
        validation=validation,
    )
    artifact_manifest = _artifact_manifest(metadata)
    metadata_json.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    artifact_manifest_json.write_text(
        json.dumps(artifact_manifest, indent=2),
        encoding="utf-8",
    )
    training_summary_json.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    training_report_md.write_text(_training_report(metadata), encoding="utf-8")

    return OpsModelTrainingResult(
        model_dir=model_dir,
        model_file=model_file,
        metadata_json=metadata_json,
        artifact_manifest_json=artifact_manifest_json,
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


def validate_grouped_random_forest(
    feature_rows: list[FlowFeatures],
    *,
    config: SupervisedDetectorConfig,
    requested_folds: int = DEFAULT_GROUPED_VALIDATION_FOLDS,
) -> OpsGroupedValidationResult:
    if requested_folds < 2:
        return OpsGroupedValidationResult(
            strategy="stratified_group_kfold",
            requested_folds=requested_folds,
            executed_folds=0,
            skipped_reason="requested_folds must be at least 2",
            folds=(),
            predictions=(),
        )

    labels = [row.label for row in feature_rows]
    beacon_count = labels.count("beacon")
    benign_count = labels.count("benign")
    group_ids = [_flow_key_text(row) for row in feature_rows]
    unique_group_count = len(set(group_ids))
    executable_folds = min(
        requested_folds,
        beacon_count,
        benign_count,
        unique_group_count,
    )
    if executable_folds < 2:
        return OpsGroupedValidationResult(
            strategy="stratified_group_kfold",
            requested_folds=requested_folds,
            executed_folds=0,
            skipped_reason=(
                "Need at least two benign and two beacon grouped flows for "
                "grouped validation."
            ),
            folds=(),
            predictions=(),
        )

    splitter = StratifiedGroupKFold(
        n_splits=executable_folds,
        shuffle=True,
        random_state=config.random_state,
    )
    numeric_labels = [1 if label == "beacon" else 0 for label in labels]
    folds: list[OpsGroupedValidationFold] = []
    validation_predictions: list[OpsValidationPrediction] = []
    for fold_number, (train_indices, validation_indices) in enumerate(
        splitter.split(
            X=list(range(len(feature_rows))),
            y=numeric_labels,
            groups=group_ids,
        ),
        start=1,
    ):
        training_rows = [feature_rows[index] for index in train_indices]
        validation_rows = [feature_rows[index] for index in validation_indices]
        model = fit_supervised_detector(
            training_rows,
            detector_type="random_forest",
            config=config,
        )
        predictions = detect_flow_feature_rows_supervised(validation_rows, model=model)
        validation_predictions.extend(
            OpsValidationPrediction(
                fold=fold_number,
                true_label=row.label,
                score=prediction.score,
            )
            for row, prediction in zip(validation_rows, predictions, strict=True)
        )
        metrics = calculate_classification_metrics(
            [row.label for row in validation_rows],
            [prediction.predicted_label for prediction in predictions],
        )
        folds.append(
            OpsGroupedValidationFold(
                fold=fold_number,
                train_flow_count=len(training_rows),
                validation_flow_count=len(validation_rows),
                validation_group_count=len(
                    {group_ids[index] for index in validation_indices}
                ),
                metrics=metrics,
            )
        )

    return OpsGroupedValidationResult(
        strategy="stratified_group_kfold",
        requested_folds=requested_folds,
        executed_folds=len(folds),
        skipped_reason=None,
        folds=tuple(folds),
        predictions=tuple(validation_predictions),
    )


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
    validation: OpsGroupedValidationResult,
) -> dict[str, Any]:
    return {
        "schema_version": OPS_MODEL_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "detector_name": model.detector_name,
        "detector_type": model.detector_type,
        "model_file": OPS_MODEL_FILE,
        "input_contract": "normalized_csv_with_label",
        "label_column": label_column,
        "label_mapping": {
            "benign": 0,
            "beacon": 1,
            "unknown": "skipped",
        },
        "training_data": {
            "source_files": [str(path) for path in train_paths],
            "loaded_event_count": loaded_event_count,
            "training_event_count": training_event_count,
            "skipped_unknown_event_count": skipped_unknown_event_count,
            "training_flow_count": flow_count,
            "beacon_training_flow_count": model.beacon_training_flow_count,
            "benign_training_flow_count": model.benign_training_flow_count,
            "training_groups": [_flow_key_text(row) for row in feature_rows],
        },
        "flow_grouping_key": [
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "direction",
        ],
        "src_port_policy": "captured_but_not_grouped",
        "score_time_windowing": "whole_file_batch",
        "loaded_event_count": loaded_event_count,
        "training_event_count": training_event_count,
        "skipped_unknown_event_count": skipped_unknown_event_count,
        "training_flow_count": flow_count,
        "beacon_training_flow_count": model.beacon_training_flow_count,
        "benign_training_flow_count": model.benign_training_flow_count,
        "feature_names": list(model.config.feature_names),
        "feature_count": len(model.config.feature_names),
        "config": asdict(model.config),
        "validation": _validation_metadata(validation),
        "threshold_profiles": threshold_profile_metadata(validation),
        "runtime_environment": runtime_environment(),
        "persistence": {
            "format": "pickle",
            "trusted_source_required": True,
            "load_warning": (
                "Only load model artifacts produced by a trusted run of this project."
            ),
            "version_compatibility": (
                "Use the recorded dependency versions when reproducing or deploying."
            ),
        },
        "intended_use": (
            "Operational batch scoring of normalized flow/event CSV inputs. "
            "Synthetic-trained artifacts are for demos and smoke tests only."
        ),
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
            f"- Feature count: {metadata['feature_count']}",
            f"- Prediction threshold: {metadata['config']['prediction_threshold']}",
            f"- Validation strategy: `{metadata['validation']['strategy']}`",
            f"- Validation folds: {metadata['validation']['executed_folds']}",
            f"- Validation F1 mean: {metadata['validation']['metrics']['mean_f1_score']:.3f}",
            "- Validation FPR mean: "
            f"{metadata['validation']['metrics']['mean_false_positive_rate']:.3f}",
            "",
            "## Threshold Profiles",
            "",
            "| Profile | Threshold | Optimized Metric | F1 | Recall | FPR |",
            "| --- | ---: | --- | ---: | ---: | ---: |",
            *[
                _threshold_profile_report_row(name, profile)
                for name, profile in metadata["threshold_profiles"].items()
            ],
            "",
            "## Artifact Manifest",
            "",
            "| File | Role |",
            "| --- | --- |",
            *[
                f"| `{artifact['path']}` | {artifact['role']} |"
                for artifact in _artifact_files()
            ],
            "",
            "## Reproducibility",
            "",
            f"- Python: `{metadata['runtime_environment']['python_version']}`",
            "- Dependencies: "
            + ", ".join(
                f"`{name}=={value}`"
                for name, value in metadata["runtime_environment"][
                    "dependency_versions"
                ].items()
            ),
            "",
            "## Notes",
            "",
            "This model was trained from normalized labelled CSV rows. Dataset-specific",
            "sources should be adapted into that schema before training.",
            "Only load model artifacts produced by a trusted run of this project.",
            "",
        ]
    )


def _validation_metadata(validation: OpsGroupedValidationResult) -> dict[str, Any]:
    metrics = summarize_metric_spread([fold.metrics for fold in validation.folds])
    return {
        "strategy": validation.strategy,
        "requested_folds": validation.requested_folds,
        "executed_folds": validation.executed_folds,
        "skipped_reason": validation.skipped_reason,
        "metrics": asdict(metrics),
        "folds": [
            {
                "fold": fold.fold,
                "train_flow_count": fold.train_flow_count,
                "validation_flow_count": fold.validation_flow_count,
                "validation_group_count": fold.validation_group_count,
                "metrics": asdict(fold.metrics),
            }
            for fold in validation.folds
        ],
        "out_of_fold_prediction_count": len(validation.predictions),
    }


def threshold_profile_metadata(
    validation: OpsGroupedValidationResult,
) -> dict[str, dict[str, Any]]:
    if not validation.predictions:
        fallback = _threshold_profile(
            threshold=DEFAULT_OPERATIONAL_RF_THRESHOLD,
            optimized_metric="fallback_default_no_grouped_validation_predictions",
            metrics=calculate_classification_metrics([], []),
        )
        return {
            "conservative": fallback,
            "balanced": fallback,
            "sensitive": fallback,
        }

    candidates = _candidate_thresholds([prediction.score for prediction in validation.predictions])
    evaluations = [
        _evaluate_threshold(validation.predictions, threshold)
        for threshold in candidates
    ]
    return {
        "conservative": _select_threshold_profile(
            evaluations,
            optimized_metric="min_false_positive_rate_then_precision",
            key=lambda row: (
                -row["metrics"]["false_positive_rate"],
                row["metrics"]["precision"],
                row["metrics"]["f1_score"],
                row["metrics"]["recall"],
                row["threshold"],
            ),
        ),
        "balanced": _select_threshold_profile(
            evaluations,
            optimized_metric="max_f1",
            key=lambda row: (
                row["metrics"]["f1_score"],
                row["metrics"]["recall"],
                row["metrics"]["precision"],
                -abs(row["metrics"]["false_positive_rate"] - 0.1),
            ),
        ),
        "sensitive": _select_threshold_profile(
            evaluations,
            optimized_metric="max_recall_then_f1",
            key=lambda row: (
                row["metrics"]["recall"],
                row["metrics"]["f1_score"],
                row["metrics"]["precision"],
                -row["metrics"]["false_positive_rate"],
                -row["threshold"],
            ),
        ),
    }


def threshold_for_profile(
    model_artifact: OpsModelArtifact,
    profile: ThresholdProfileName,
) -> float:
    profiles = model_artifact.metadata.get("threshold_profiles") or {}
    profile_metadata = profiles.get(profile)
    if not profile_metadata:
        return model_artifact.model.config.prediction_threshold
    return float(profile_metadata["threshold"])


def model_with_threshold_profile(
    model_artifact: OpsModelArtifact,
    profile: ThresholdProfileName,
) -> SupervisedDetectorModel:
    threshold = threshold_for_profile(model_artifact, profile)
    return replace(
        model_artifact.model,
        config=replace(model_artifact.model.config, prediction_threshold=threshold),
    )


def _candidate_thresholds(scores: list[float]) -> list[float]:
    clipped_scores = sorted({min(max(score, 0.0), 1.0) for score in scores})
    candidates = {0.0, 1.0}
    candidates.update(clipped_scores)
    candidates.update(
        (left + right) / 2.0
        for left, right in zip(clipped_scores, clipped_scores[1:], strict=False)
    )
    return sorted(candidates)


def _evaluate_threshold(
    predictions: tuple[OpsValidationPrediction, ...],
    threshold: float,
) -> dict[str, Any]:
    predicted_labels = [
        "beacon" if prediction.score >= threshold else "benign"
        for prediction in predictions
    ]
    true_labels = [prediction.true_label for prediction in predictions]
    metrics = calculate_classification_metrics(true_labels, predicted_labels)
    return _threshold_profile(
        threshold=threshold,
        optimized_metric="candidate",
        metrics=metrics,
    )


def _select_threshold_profile(
    evaluations: list[dict[str, Any]],
    *,
    optimized_metric: str,
    key,
) -> dict[str, Any]:
    selected = max(evaluations, key=key)
    return {
        **selected,
        "optimized_metric": optimized_metric,
        "selection_method": "out_of_fold_grouped_validation",
    }


def _threshold_profile(
    *,
    threshold: float,
    optimized_metric: str,
    metrics: ClassificationMetrics,
) -> dict[str, Any]:
    return {
        "threshold": float(threshold),
        "optimized_metric": optimized_metric,
        "metrics": asdict(metrics),
    }


def _threshold_profile_report_row(name: str, profile: dict[str, Any]) -> str:
    metrics = profile["metrics"]
    return (
        f"| {name} | {profile['threshold']:.3f} | "
        f"{profile['optimized_metric']} | {metrics['f1_score']:.3f} | "
        f"{metrics['recall']:.3f} | {metrics['false_positive_rate']:.3f} |"
    )


def _artifact_manifest(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": metadata["schema_version"],
        "created_at_utc": metadata["created_at_utc"],
        "artifact_type": "operational_random_forest_model",
        "detector_name": metadata["detector_name"],
        "input_contract": metadata["input_contract"],
        "files": _artifact_files(),
        "feature_names": metadata["feature_names"],
        "label_mapping": metadata["label_mapping"],
        "training_data": metadata["training_data"],
        "validation": metadata["validation"],
        "threshold_profiles": metadata["threshold_profiles"],
        "runtime_environment": metadata["runtime_environment"],
        "persistence": metadata["persistence"],
    }


def _artifact_files() -> list[dict[str, str]]:
    return [
        {
            "path": OPS_MODEL_FILE,
            "role": "Serialized supervised detector. Load only from a trusted source.",
        },
        {
            "path": OPS_MODEL_METADATA_FILE,
            "role": "Full model metadata, features, labels, validation, and environment.",
        },
        {
            "path": OPS_MODEL_ARTIFACT_MANIFEST_FILE,
            "role": "Concise manifest for artifact inspection and deployment checks.",
        },
        {
            "path": OPS_MODEL_TRAINING_SUMMARY_FILE,
            "role": "Machine-readable training summary.",
        },
        {
            "path": OPS_MODEL_TRAINING_REPORT_FILE,
            "role": "Human-readable training report.",
        },
    ]


def runtime_environment() -> dict[str, Any]:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "dependency_versions": {
            package: _package_version(package)
            for package in (
                "numpy",
                "pandas",
                "scikit-learn",
                "matplotlib",
            )
        },
    }


def _package_version(package: str) -> str:
    try:
        return version(package)
    except PackageNotFoundError:
        return "not_installed"


def _flow_key_text(row: Flow | FlowFeatures) -> str:
    key = row.flow_key
    return (
        f"{key.src_ip}|{key.direction or ''}|"
        f"{key.dst_ip}:{key.dst_port}/{key.protocol}"
    )
