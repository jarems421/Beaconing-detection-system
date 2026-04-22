from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey

from .rules import PredictedLabel
from .statistical import DEFAULT_STATISTICAL_FEATURES

AnomalyDetectorType = Literal["isolation_forest", "local_outlier_factor"]

ISOLATION_FOREST_NAME = "isolation_forest_v1"
LOCAL_OUTLIER_FACTOR_NAME = "local_outlier_factor_v1"
DEFAULT_ANOMALY_FEATURES = DEFAULT_STATISTICAL_FEATURES


@dataclass(frozen=True, slots=True)
class AnomalyDetectorConfig:
    feature_names: tuple[str, ...] = DEFAULT_ANOMALY_FEATURES
    missing_value: float = 0.0
    contamination: float = 0.03
    calibration_fraction: float = 0.25
    isolation_forest_estimators: int = 200
    random_state: int = 42
    lof_neighbors: int = 20
    top_contribution_count: int = 5


@dataclass(frozen=True, slots=True)
class AnomalyDetectorModel:
    detector_name: str
    detector_type: AnomalyDetectorType
    config: AnomalyDetectorConfig
    scaler: StandardScaler
    estimator: Any
    prediction_threshold: float
    reference_flow_count: int
    calibration_flow_count: int


@dataclass(frozen=True, slots=True)
class AnomalyContribution:
    rule_name: str
    fired: bool
    score: float
    reason: str
    feature_value: float
    z_score: float


@dataclass(frozen=True, slots=True)
class AnomalyDetectionResult:
    flow_key: FlowKey
    scenario_name: str | None
    true_label: str
    predicted_label: PredictedLabel
    score: float
    threshold: float
    contributions: tuple[AnomalyContribution, ...]

    @property
    def top_standardized_feature_deviations(self) -> tuple[str, ...]:
        """Debug aid, not model attribution.

        Isolation Forest and LOF do not expose simple per-feature reasons for a
        decision. These are the largest standardized feature deviations from
        the benign reference scaler, which helps inspect suspicious flows.
        """

        return tuple(contribution.rule_name for contribution in self.contributions)


def fit_anomaly_detector(
    feature_rows: list[FlowFeatures],
    detector_type: AnomalyDetectorType,
    config: AnomalyDetectorConfig | None = None,
) -> AnomalyDetectorModel:
    config = config or AnomalyDetectorConfig()
    benign_rows = [row for row in feature_rows if row.label == "benign"]
    if len(benign_rows) < 2:
        raise ValueError("At least two benign reference flows are required.")
    reference_rows, calibration_rows = _split_reference_and_calibration_rows(
        benign_rows,
        calibration_fraction=config.calibration_fraction,
    )
    if len(reference_rows) < 2:
        reference_rows, calibration_rows = benign_rows, benign_rows

    scaler = StandardScaler()
    reference_matrix = _feature_matrix(reference_rows, config)
    scaled_reference = scaler.fit_transform(reference_matrix)
    estimator = _fit_estimator(detector_type, scaled_reference, config)
    scaled_calibration = scaler.transform(_feature_matrix(calibration_rows, config))
    calibration_scores = [
        -float(score) for score in estimator.decision_function(scaled_calibration)
    ]

    return AnomalyDetectorModel(
        detector_name=_detector_name(detector_type),
        detector_type=detector_type,
        config=config,
        scaler=scaler,
        estimator=estimator,
        prediction_threshold=_quantile(calibration_scores, 1.0 - config.contamination),
        reference_flow_count=len(reference_rows),
        calibration_flow_count=len(calibration_rows),
    )


def detect_flow_features_anomaly(
    features: FlowFeatures,
    model: AnomalyDetectorModel,
) -> AnomalyDetectionResult:
    return detect_flow_feature_rows_anomaly([features], model=model)[0]


def detect_flow_feature_rows_anomaly(
    feature_rows: list[FlowFeatures],
    model: AnomalyDetectorModel,
) -> list[AnomalyDetectionResult]:
    if not feature_rows:
        return []

    matrix = _feature_matrix(feature_rows, model.config)
    scaled = model.scaler.transform(matrix)
    # sklearn decision_function uses positive values for inliers; invert it so
    # higher scores consistently mean "more anomalous" across detectors.
    anomaly_scores = [-float(score) for score in model.estimator.decision_function(scaled)]

    results: list[AnomalyDetectionResult] = []
    for features, score, scaled_values in zip(
        feature_rows,
        anomaly_scores,
        scaled,
        strict=True,
    ):
        predicted_label: PredictedLabel = (
            "beacon" if score >= model.prediction_threshold else "benign"
        )
        results.append(
            AnomalyDetectionResult(
                flow_key=features.flow_key,
                scenario_name=features.scenario_name,
                true_label=features.label,
                predicted_label=predicted_label,
                score=score,
                threshold=model.prediction_threshold,
                contributions=_top_standardized_feature_deviations(
                    features,
                    scaled_values,
                    model,
                ),
            )
        )
    return results


def score_flow_features_anomaly(
    features: FlowFeatures,
    model: AnomalyDetectorModel,
) -> tuple[float, tuple[AnomalyContribution, ...]]:
    result = detect_flow_features_anomaly(features, model=model)
    return result.score, result.contributions


def _fit_estimator(
    detector_type: AnomalyDetectorType,
    scaled_reference,
    config: AnomalyDetectorConfig,
):
    if detector_type == "isolation_forest":
        estimator = IsolationForest(
            n_estimators=config.isolation_forest_estimators,
            contamination=config.contamination,
            random_state=config.random_state,
        )
        return estimator.fit(scaled_reference)
    if detector_type == "local_outlier_factor":
        n_neighbors = min(config.lof_neighbors, max(1, len(scaled_reference) - 1))
        estimator = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=config.contamination,
            novelty=True,
        )
        return estimator.fit(scaled_reference)
    raise ValueError(f"Unsupported anomaly detector type: {detector_type}")


def _feature_matrix(
    feature_rows: list[FlowFeatures],
    config: AnomalyDetectorConfig,
) -> list[list[float]]:
    return [
        [
            _feature_value(row, feature_name, missing_value=config.missing_value)
            for feature_name in config.feature_names
        ]
        for row in feature_rows
    ]


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
    reference_count = max(2, int(round(len(ordered) * (1.0 - calibration_fraction))))
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


def _top_standardized_feature_deviations(
    features: FlowFeatures,
    scaled_values,
    model: AnomalyDetectorModel,
) -> tuple[AnomalyContribution, ...]:
    contributions: list[AnomalyContribution] = []
    for feature_name, z_score in zip(model.config.feature_names, scaled_values, strict=True):
        feature_value = _feature_value(
            features,
            feature_name,
            missing_value=model.config.missing_value,
        )
        contributions.append(
            AnomalyContribution(
                rule_name=feature_name,
                fired=True,
                score=abs(float(z_score)),
                reason=(
                    f"{feature_name} standardized feature deviation "
                    f"{float(z_score):.3f}"
                ),
                feature_value=feature_value,
                z_score=float(z_score),
            )
        )
    return tuple(
        sorted(contributions, key=lambda contribution: contribution.score, reverse=True)[
            : model.config.top_contribution_count
        ]
    )


def _detector_name(detector_type: AnomalyDetectorType) -> str:
    if detector_type == "isolation_forest":
        return ISOLATION_FOREST_NAME
    if detector_type == "local_outlier_factor":
        return LOCAL_OUTLIER_FACTOR_NAME
    raise ValueError(f"Unsupported anomaly detector type: {detector_type}")


def _quantile(values: list[float], quantile: float) -> float:
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be in the range [0, 1].")
    if not values:
        raise ValueError("Cannot calculate a quantile from an empty list.")
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * quantile))
    return ordered[index]
