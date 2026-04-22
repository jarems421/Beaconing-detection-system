from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey

from .rules import PredictedLabel

DEFAULT_STATISTICAL_FEATURES = (
    "event_count",
    "flow_duration_seconds",
    "inter_arrival_cv",
    "trimmed_interarrival_cv",
    "interarrival_iqr_seconds",
    "interarrival_mad_seconds",
    "near_median_interarrival_fraction",
    "dominant_interval_fraction",
    "periodicity_score",
    "burst_count",
    "avg_burst_size",
    "burst_to_idle_ratio",
    "size_cv",
)
STATISTICAL_BASELINE_NAME = "statistical_zscore_baseline_v1"


@dataclass(frozen=True, slots=True)
class StatisticalBaselineConfig:
    feature_names: tuple[str, ...] = DEFAULT_STATISTICAL_FEATURES
    benign_score_quantile: float = 0.99
    calibration_fraction: float = 0.25
    min_reference_std: float = 1e-6
    missing_value: float = 0.0
    top_contribution_count: int = 5


@dataclass(frozen=True, slots=True)
class FeatureReference:
    feature_name: str
    mean: float
    std: float


@dataclass(frozen=True, slots=True)
class StatisticalBaselineModel:
    config: StatisticalBaselineConfig
    references: tuple[FeatureReference, ...]
    prediction_threshold: float
    reference_flow_count: int
    calibration_flow_count: int


@dataclass(frozen=True, slots=True)
class StatisticalContribution:
    rule_name: str
    fired: bool
    score: float
    reason: str
    feature_value: float
    reference_mean: float
    reference_std: float
    z_score: float


@dataclass(frozen=True, slots=True)
class StatisticalDetectionResult:
    flow_key: FlowKey
    scenario_name: str | None
    true_label: str
    predicted_label: PredictedLabel
    score: float
    threshold: float
    contributions: tuple[StatisticalContribution, ...]

    @property
    def top_contributing_features(self) -> tuple[str, ...]:
        return tuple(contribution.rule_name for contribution in self.contributions)


def fit_statistical_baseline(
    feature_rows: list[FlowFeatures],
    config: StatisticalBaselineConfig | None = None,
) -> StatisticalBaselineModel:
    config = config or StatisticalBaselineConfig()
    benign_rows = [row for row in feature_rows if row.label == "benign"]
    if not benign_rows:
        raise ValueError("At least one benign reference flow is required.")
    reference_rows, calibration_rows = _split_reference_and_calibration_rows(
        benign_rows,
        calibration_fraction=config.calibration_fraction,
    )

    references = tuple(
        _fit_feature_reference(feature_name, reference_rows, config)
        for feature_name in config.feature_names
    )
    temporary_model = StatisticalBaselineModel(
        config=config,
        references=references,
        prediction_threshold=0.0,
        reference_flow_count=len(reference_rows),
        calibration_flow_count=len(calibration_rows),
    )
    reference_scores = [
        score_flow_features(row, temporary_model)[0] for row in calibration_rows
    ]
    return StatisticalBaselineModel(
        config=config,
        references=references,
        prediction_threshold=_quantile(reference_scores, config.benign_score_quantile),
        reference_flow_count=len(reference_rows),
        calibration_flow_count=len(calibration_rows),
    )


def detect_flow_features_statistical(
    features: FlowFeatures,
    model: StatisticalBaselineModel,
) -> StatisticalDetectionResult:
    score, contributions = score_flow_features(features, model)
    predicted_label: PredictedLabel = (
        "beacon" if score >= model.prediction_threshold else "benign"
    )
    return StatisticalDetectionResult(
        flow_key=features.flow_key,
        scenario_name=features.scenario_name,
        true_label=features.label,
        predicted_label=predicted_label,
        score=score,
        threshold=model.prediction_threshold,
        contributions=contributions,
    )


def detect_flow_feature_rows_statistical(
    feature_rows: list[FlowFeatures],
    model: StatisticalBaselineModel,
) -> list[StatisticalDetectionResult]:
    return [
        detect_flow_features_statistical(row, model=model)
        for row in feature_rows
    ]


def score_flow_features(
    features: FlowFeatures,
    model: StatisticalBaselineModel,
) -> tuple[float, tuple[StatisticalContribution, ...]]:
    z_scores: list[float] = []
    contributions: list[StatisticalContribution] = []
    for reference in model.references:
        value = _feature_value(
            features,
            reference.feature_name,
            missing_value=model.config.missing_value,
        )
        z_score = (value - reference.mean) / reference.std
        z_scores.append(z_score)
        contributions.append(
            StatisticalContribution(
                rule_name=reference.feature_name,
                fired=True,
                score=abs(z_score),
                reason=(
                    f"{reference.feature_name} z-score {z_score:.3f} "
                    f"from benign reference"
                ),
                feature_value=value,
                reference_mean=reference.mean,
                reference_std=reference.std,
                z_score=z_score,
            )
        )

    distance = math.sqrt(sum(z_score**2 for z_score in z_scores) / len(z_scores))
    top_contributions = tuple(
        sorted(contributions, key=lambda contribution: contribution.score, reverse=True)[
            : model.config.top_contribution_count
        ]
    )
    return distance, top_contributions


def _fit_feature_reference(
    feature_name: str,
    reference_rows: list[FlowFeatures],
    config: StatisticalBaselineConfig,
) -> FeatureReference:
    values = [
        _feature_value(row, feature_name, missing_value=config.missing_value)
        for row in reference_rows
    ]
    mean_value = sum(values) / len(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    std_value = max(variance**0.5, config.min_reference_std)
    return FeatureReference(
        feature_name=feature_name,
        mean=mean_value,
        std=std_value,
    )


def _feature_value(
    features: FlowFeatures,
    feature_name: str,
    missing_value: float,
) -> float:
    value = getattr(features, feature_name)
    if value is None:
        return missing_value
    return float(value)


def _split_reference_and_calibration_rows(
    rows: list[FlowFeatures],
    *,
    calibration_fraction: float,
) -> tuple[list[FlowFeatures], list[FlowFeatures]]:
    if not 0 < calibration_fraction < 1:
        raise ValueError("calibration_fraction must be between 0 and 1.")
    ordered = sorted(rows, key=_stable_feature_row_key)
    if len(ordered) == 1:
        return ordered, ordered
    reference_count = max(1, int(round(len(ordered) * (1.0 - calibration_fraction))))
    reference_count = min(reference_count, len(ordered) - 1)
    return ordered[:reference_count], ordered[reference_count:]


def _stable_feature_row_key(row: FlowFeatures) -> str:
    key = row.flow_key
    identity = "|".join(
        (
            key.src_ip,
            key.src_port or "",
            key.direction or "",
            key.dst_ip,
            str(key.dst_port),
            key.protocol,
            row.scenario_name or "",
            row.label,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _quantile(values: list[float], quantile: float) -> float:
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be in the range [0, 1].")
    if not values:
        raise ValueError("Cannot calculate a quantile from an empty list.")

    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * quantile))
    return ordered[index]
