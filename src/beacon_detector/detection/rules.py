from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey

PredictedLabel = Literal["benign", "beacon"]


@dataclass(frozen=True, slots=True)
class RuleThresholds:
    min_event_count: int = 5
    min_flow_duration_seconds: float = 30.0
    prediction_threshold: float = 2.2

    periodic_cv_threshold: float = 0.30
    periodic_iqr_fraction_threshold: float = 0.50
    timing_min_event_count: int = 10
    strong_periodic_cv_threshold: float = 0.12
    strong_periodic_iqr_fraction_threshold: float = 0.20

    stable_size_cv_threshold: float = 0.30
    constant_size_cv_threshold: float = 0.02
    constant_size_min_duration_seconds: float = 120.0

    long_repetition_min_event_count: int = 12
    long_repetition_min_duration_seconds: float = 600.0
    long_repetition_min_mean_interarrival_seconds: float = 20.0
    long_repetition_max_mean_interarrival_seconds: float = 240.0

    moderate_jitter_min_event_count: int = 8
    moderate_jitter_cv_threshold: float = 0.18
    moderate_jitter_size_cv_threshold: float = 0.25

    burst_min_count: int = 2
    burst_min_avg_size: float = 2.0
    burst_min_avg_sleep_seconds: float = 30.0
    burst_strong_sleep_seconds: float = 120.0
    burst_repeated_count: int = 3
    burst_max_burst_to_idle_ratio: float = 0.35

    periodic_timing_score: float = 1.1
    compact_timing_spread_score: float = 0.5
    stable_size_score: float = 0.4
    sustained_flow_score: float = 0.2
    burst_structure_score: float = 2.0
    constant_size_repetition_score: float = 1.6
    long_low_rate_repetition_score: float = 2.0
    moderate_jitter_repetition_score: float = 0.5


FROZEN_RULE_BASELINE_NAME = "rule_baseline_v2_hardened_final"
FROZEN_RULE_BASELINE_THRESHOLDS = RuleThresholds()
HIGH_PRECISION_RULE_BASELINE_THRESHOLDS = replace(
    FROZEN_RULE_BASELINE_THRESHOLDS,
    prediction_threshold=2.8,
)


@dataclass(frozen=True, slots=True)
class RuleContribution:
    rule_name: str
    fired: bool
    score: float
    reason: str


@dataclass(frozen=True, slots=True)
class RuleDetectionResult:
    flow_key: FlowKey
    scenario_name: str | None
    true_label: str
    predicted_label: PredictedLabel
    score: float
    threshold: float
    contributions: tuple[RuleContribution, ...]

    @property
    def triggered_reasons(self) -> tuple[str, ...]:
        return tuple(
            contribution.reason
            for contribution in self.contributions
            if contribution.fired and contribution.score > 0
        )


def detect_flow_features(
    features: FlowFeatures,
    thresholds: RuleThresholds | None = None,
) -> RuleDetectionResult:
    thresholds = thresholds or RuleThresholds()
    contributions = _score_rules(features, thresholds)
    score = sum(contribution.score for contribution in contributions if contribution.fired)
    predicted_label: PredictedLabel = (
        "beacon" if score >= thresholds.prediction_threshold else "benign"
    )

    return RuleDetectionResult(
        flow_key=features.flow_key,
        scenario_name=features.scenario_name,
        true_label=features.label,
        predicted_label=predicted_label,
        score=score,
        threshold=thresholds.prediction_threshold,
        contributions=tuple(contributions),
    )


def detect_flow_feature_rows(
    feature_rows: list[FlowFeatures],
    thresholds: RuleThresholds | None = None,
) -> list[RuleDetectionResult]:
    return [detect_flow_features(row, thresholds=thresholds) for row in feature_rows]


def _score_rules(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> list[RuleContribution]:
    contributions = [_minimum_event_count_rule(features, thresholds)]
    if features.event_count < thresholds.min_event_count:
        return contributions

    contributions.extend(
        [
            _periodic_timing_rule(features, thresholds),
            _compact_timing_spread_rule(features, thresholds),
            _stable_size_rule(features, thresholds),
            _sustained_flow_rule(features, thresholds),
            _burst_structure_rule(features, thresholds),
            _constant_size_repetition_rule(features, thresholds),
            _long_low_rate_repetition_rule(features, thresholds),
            _moderate_jitter_repetition_rule(features, thresholds),
        ]
    )
    return contributions


def _minimum_event_count_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    fired = features.event_count >= thresholds.min_event_count
    return RuleContribution(
        rule_name="minimum_event_count",
        fired=fired,
        score=0.0,
        reason=(
            f"event_count {features.event_count} meets minimum {thresholds.min_event_count}"
            if fired
            else f"event_count {features.event_count} is below minimum {thresholds.min_event_count}"
        ),
    )


def _periodic_timing_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    cv = features.inter_arrival_cv
    duration = features.flow_duration_seconds
    enough_timing_support = (
        features.event_count >= thresholds.timing_min_event_count
        or (cv is not None and cv <= thresholds.strong_periodic_cv_threshold)
    )
    fired = (
        cv is not None
        and duration is not None
        and duration >= thresholds.min_flow_duration_seconds
        and cv <= thresholds.periodic_cv_threshold
        and enough_timing_support
    )
    return RuleContribution(
        rule_name="low_interarrival_variability",
        fired=fired,
        score=thresholds.periodic_timing_score if fired else 0.0,
        reason=(
            f"inter-arrival CV {cv:.3f} <= {thresholds.periodic_cv_threshold:.3f}"
            if fired and cv is not None
            else "inter-arrival variability is not low enough"
        ),
    )


def _compact_timing_spread_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    iqr = features.interarrival_iqr_seconds
    mean = features.mean_interarrival_seconds
    limit = mean * thresholds.periodic_iqr_fraction_threshold if mean is not None else None
    strong_limit = (
        mean * thresholds.strong_periodic_iqr_fraction_threshold
        if mean is not None
        else None
    )
    enough_timing_support = (
        features.event_count >= thresholds.timing_min_event_count
        or (iqr is not None and strong_limit is not None and iqr <= strong_limit)
    )
    fired = (
        iqr is not None
        and limit is not None
        and iqr <= limit
        and enough_timing_support
    )
    return RuleContribution(
        rule_name="compact_interarrival_spread",
        fired=fired,
        score=thresholds.compact_timing_spread_score if fired else 0.0,
        reason=(
            f"inter-arrival IQR {iqr:.3f}s <= {limit:.3f}s"
            if fired and iqr is not None and limit is not None
            else "inter-arrival spread is too wide"
        ),
    )


def _stable_size_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    size_cv = features.size_cv
    fired = size_cv is not None and size_cv <= thresholds.stable_size_cv_threshold
    return RuleContribution(
        rule_name="stable_payload_size",
        fired=fired,
        score=thresholds.stable_size_score if fired else 0.0,
        reason=(
            f"size CV {size_cv:.3f} <= {thresholds.stable_size_cv_threshold:.3f}"
            if fired and size_cv is not None
            else "payload sizes are not stable enough"
        ),
    )


def _sustained_flow_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    duration = features.flow_duration_seconds
    fired = duration is not None and duration >= thresholds.min_flow_duration_seconds
    return RuleContribution(
        rule_name="sustained_repeated_communication",
        fired=fired,
        score=thresholds.sustained_flow_score if fired else 0.0,
        reason=(
            f"flow duration {duration:.3f}s >= {thresholds.min_flow_duration_seconds:.3f}s"
            if fired and duration is not None
            else "flow duration is too short"
        ),
    )


def _burst_structure_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    burst_count = features.burst_count or 0
    avg_size = features.avg_burst_size
    avg_sleep = features.avg_sleep_duration_seconds
    ratio = features.burst_to_idle_ratio
    fired = (
        burst_count >= thresholds.burst_min_count
        and avg_size is not None
        and avg_size >= thresholds.burst_min_avg_size
        and avg_sleep is not None
        and avg_sleep >= thresholds.burst_min_avg_sleep_seconds
        and ratio is not None
        and ratio <= thresholds.burst_max_burst_to_idle_ratio
        and (
            avg_sleep >= thresholds.burst_strong_sleep_seconds
            or burst_count >= thresholds.burst_repeated_count
        )
    )
    return RuleContribution(
        rule_name="burst_sleep_structure",
        fired=fired,
        score=thresholds.burst_structure_score if fired else 0.0,
        reason=(
            "repeated bursts separated by longer sleeps"
            if fired
            else "burst/sleep structure is not strong enough"
        ),
    )


def _constant_size_repetition_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    size_cv = features.size_cv
    duration = features.flow_duration_seconds
    fired = (
        size_cv is not None
        and duration is not None
        and size_cv <= thresholds.constant_size_cv_threshold
        and duration >= thresholds.constant_size_min_duration_seconds
    )
    return RuleContribution(
        rule_name="constant_size_repetition",
        fired=fired,
        score=thresholds.constant_size_repetition_score if fired else 0.0,
        reason=(
            "repeated communication has nearly constant payload size"
            if fired
            else "payload size is not constant enough over a sustained flow"
        ),
    )


def _long_low_rate_repetition_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    duration = features.flow_duration_seconds
    mean_iat = features.mean_interarrival_seconds
    fired = (
        duration is not None
        and mean_iat is not None
        and features.event_count >= thresholds.long_repetition_min_event_count
        and duration >= thresholds.long_repetition_min_duration_seconds
        and mean_iat >= thresholds.long_repetition_min_mean_interarrival_seconds
        and mean_iat <= thresholds.long_repetition_max_mean_interarrival_seconds
    )
    return RuleContribution(
        rule_name="long_low_rate_repetition",
        fired=fired,
        score=thresholds.long_low_rate_repetition_score if fired else 0.0,
        reason=(
            "many events repeat over a long low-rate flow"
            if fired
            else "flow is not long/repeated enough for jitter-tolerant matching"
        ),
    )


def _moderate_jitter_repetition_rule(
    features: FlowFeatures,
    thresholds: RuleThresholds,
) -> RuleContribution:
    timing_cv = features.inter_arrival_cv
    size_cv = features.size_cv
    fired = (
        timing_cv is not None
        and size_cv is not None
        and features.event_count >= thresholds.moderate_jitter_min_event_count
        and timing_cv <= thresholds.moderate_jitter_cv_threshold
        and size_cv <= thresholds.moderate_jitter_size_cv_threshold
    )
    return RuleContribution(
        rule_name="moderate_jitter_repetition",
        fired=fired,
        score=thresholds.moderate_jitter_repetition_score if fired else 0.0,
        reason=(
            "timing is moderately regular while size jitter stays bounded"
            if fired
            else "timing/size jitter is too wide for moderate-jitter matching"
        ),
    )
