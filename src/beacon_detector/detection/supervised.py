from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey

from .rules import PredictedLabel
SupervisedDetectorType = Literal["logistic_regression", "random_forest"]

LOGISTIC_REGRESSION_NAME = "logistic_regression_v1"
RANDOM_FOREST_NAME = "random_forest_v1"
DEFAULT_SUPERVISED_FEATURES = (
    "event_count",
    "flow_duration_seconds",
    "inter_arrival_cv",
    "trimmed_interarrival_cv",
    "interarrival_iqr_seconds",
    "interarrival_mad_seconds",
    "near_median_interarrival_fraction",
    "interarrival_within_10pct_median_fraction",
    "interarrival_within_20pct_median_fraction",
    "interarrival_within_30pct_median_fraction",
    "dominant_interval_fraction",
    "dominant_interval_bin_fraction",
    "interval_bin_count",
    "adjacent_gap_similarity_fraction",
    "longest_similar_gap_run",
    "gap_range_median_ratio",
    "interarrival_median_absolute_percentage_deviation",
    "periodicity_score",
    "burst_count",
    "avg_burst_size",
    "burst_size_cv",
    "sleep_duration_cv",
    "within_burst_gap_consistency",
    "burst_to_idle_ratio",
    "size_cv",
    "dominant_size_bin_fraction",
    "size_bin_count",
    "normalized_size_range",
    "near_median_size_fraction",
)


@dataclass(frozen=True, slots=True)
class SupervisedDetectorConfig:
    feature_names: tuple[str, ...] = DEFAULT_SUPERVISED_FEATURES
    missing_value: float = 0.0
    prediction_threshold: float = 0.5
    random_state: int = 42
    logistic_max_iter: int = 1000
    random_forest_estimators: int = 200
    random_forest_max_depth: int | None = 8
    random_forest_min_samples_leaf: int = 2
    top_contribution_count: int = 8


@dataclass(frozen=True, slots=True)
class SupervisedDetectorModel:
    detector_name: str
    detector_type: SupervisedDetectorType
    config: SupervisedDetectorConfig
    scaler: StandardScaler
    estimator: Any
    training_flow_count: int
    beacon_training_flow_count: int
    benign_training_flow_count: int


@dataclass(frozen=True, slots=True)
class SupervisedContribution:
    rule_name: str
    fired: bool
    score: float
    reason: str
    feature_value: float


@dataclass(frozen=True, slots=True)
class SupervisedDetectionResult:
    flow_key: FlowKey
    scenario_name: str | None
    true_label: str
    predicted_label: PredictedLabel
    score: float
    threshold: float
    contributions: tuple[SupervisedContribution, ...]

    @property
    def top_model_features(self) -> tuple[str, ...]:
        return tuple(contribution.rule_name for contribution in self.contributions)


def fit_supervised_detector(
    feature_rows: list[FlowFeatures],
    detector_type: SupervisedDetectorType,
    config: SupervisedDetectorConfig | None = None,
) -> SupervisedDetectorModel:
    config = config or SupervisedDetectorConfig()
    if len(feature_rows) < 2:
        raise ValueError("At least two labelled training flows are required.")

    labels = [_label_to_int(row.label) for row in feature_rows]
    if len(set(labels)) < 2:
        raise ValueError("Training data must contain both benign and beacon flows.")

    scaler = StandardScaler()
    matrix = _feature_matrix(feature_rows, config)
    scaled_matrix = scaler.fit_transform(matrix)
    estimator = _fit_estimator(detector_type, scaled_matrix, labels, config)

    beacon_count = sum(labels)
    return SupervisedDetectorModel(
        detector_name=_detector_name(detector_type),
        detector_type=detector_type,
        config=config,
        scaler=scaler,
        estimator=estimator,
        training_flow_count=len(feature_rows),
        beacon_training_flow_count=beacon_count,
        benign_training_flow_count=len(feature_rows) - beacon_count,
    )


def detect_flow_features_supervised(
    features: FlowFeatures,
    model: SupervisedDetectorModel,
) -> SupervisedDetectionResult:
    return detect_flow_feature_rows_supervised([features], model=model)[0]


def detect_flow_feature_rows_supervised(
    feature_rows: list[FlowFeatures],
    model: SupervisedDetectorModel,
) -> list[SupervisedDetectionResult]:
    if not feature_rows:
        return []

    matrix = _feature_matrix(feature_rows, model.config)
    scaled_matrix = model.scaler.transform(matrix)
    probabilities = model.estimator.predict_proba(scaled_matrix)[:, 1]
    global_contributions = _top_model_contributions(model)

    results: list[SupervisedDetectionResult] = []
    for features, probability in zip(feature_rows, probabilities):
        score = float(probability)
        predicted_label: PredictedLabel = (
            "beacon" if score >= model.config.prediction_threshold else "benign"
        )
        results.append(
            SupervisedDetectionResult(
                flow_key=features.flow_key,
                scenario_name=features.scenario_name,
                true_label=features.label,
                predicted_label=predicted_label,
                score=score,
                threshold=model.config.prediction_threshold,
                contributions=_with_feature_values(features, global_contributions, model),
            )
        )
    return results


def supervised_operating_point(config: SupervisedDetectorConfig) -> str:
    return (
        f"threshold={config.prediction_threshold:g};"
        f"features={len(config.feature_names)}"
    )


def _fit_estimator(
    detector_type: SupervisedDetectorType,
    scaled_matrix,
    labels: list[int],
    config: SupervisedDetectorConfig,
):
    if detector_type == "logistic_regression":
        estimator = LogisticRegression(
            max_iter=config.logistic_max_iter,
            class_weight="balanced",
            random_state=config.random_state,
        )
        return estimator.fit(scaled_matrix, labels)
    if detector_type == "random_forest":
        estimator = RandomForestClassifier(
            n_estimators=config.random_forest_estimators,
            max_depth=config.random_forest_max_depth,
            min_samples_leaf=config.random_forest_min_samples_leaf,
            class_weight="balanced",
            random_state=config.random_state,
        )
        return estimator.fit(scaled_matrix, labels)
    raise ValueError(f"Unsupported supervised detector type: {detector_type}")


def _top_model_contributions(
    model: SupervisedDetectorModel,
) -> tuple[SupervisedContribution, ...]:
    if model.detector_type == "logistic_regression":
        coefficients = model.estimator.coef_[0]
        pairs = zip(model.config.feature_names, coefficients)
        reason_prefix = "logistic regression coefficient"
    else:
        importances = model.estimator.feature_importances_
        pairs = zip(model.config.feature_names, importances)
        reason_prefix = "random forest feature importance"

    contributions = [
        SupervisedContribution(
            rule_name=feature_name,
            fired=True,
            score=abs(float(weight)),
            reason=f"{feature_name} {reason_prefix} {float(weight):.4f}",
            feature_value=0.0,
        )
        for feature_name, weight in pairs
    ]
    return tuple(
        sorted(contributions, key=lambda contribution: contribution.score, reverse=True)[
            : model.config.top_contribution_count
        ]
    )


def _with_feature_values(
    features: FlowFeatures,
    contributions: tuple[SupervisedContribution, ...],
    model: SupervisedDetectorModel,
) -> tuple[SupervisedContribution, ...]:
    return tuple(
        SupervisedContribution(
            rule_name=contribution.rule_name,
            fired=contribution.fired,
            score=contribution.score,
            reason=contribution.reason,
            feature_value=_feature_value(
                features,
                contribution.rule_name,
                missing_value=model.config.missing_value,
            ),
        )
        for contribution in contributions
    )


def _feature_matrix(
    feature_rows: list[FlowFeatures],
    config: SupervisedDetectorConfig,
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


def _label_to_int(label: str) -> int:
    if label == "beacon":
        return 1
    if label == "benign":
        return 0
    raise ValueError(f"Unsupported label for supervised training: {label}")


def _detector_name(detector_type: SupervisedDetectorType) -> str:
    if detector_type == "logistic_regression":
        return LOGISTIC_REGRESSION_NAME
    if detector_type == "random_forest":
        return RANDOM_FOREST_NAME
    raise ValueError(f"Unsupported supervised detector type: {detector_type}")
