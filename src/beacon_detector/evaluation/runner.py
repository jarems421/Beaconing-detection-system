from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Protocol

from beacon_detector.data import (
    GenerationScenario,
    NormalTrafficProfile,
    SyntheticTrafficConfig,
    generate_combined_synthetic_dataset,
    generate_synthetic_events,
)
from beacon_detector.detection import (
    AnomalyDetectorConfig,
    AnomalyDetectorType,
    RuleThresholds,
    StatisticalBaselineConfig,
    SupervisedDetectorConfig,
    SupervisedDetectorType,
    detect_flow_feature_rows_anomaly,
    detect_flow_feature_rows,
    detect_flow_feature_rows_statistical,
    detect_flow_feature_rows_supervised,
    fit_anomaly_detector,
    fit_statistical_baseline,
    fit_supervised_detector,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import FlowKey
from beacon_detector.flows import build_flows

from .cache import FeatureCacheConfig, get_or_build_feature_rows
from .metrics import (
    ClassificationMetrics,
    MetricSpread,
    calculate_classification_metrics,
    summarize_metric_spread,
)

class DetectionContribution(Protocol):
    rule_name: str
    fired: bool
    score: float


class DetectionResult(Protocol):
    flow_key: FlowKey
    scenario_name: str | None
    true_label: str
    predicted_label: str
    score: float
    contributions: tuple[DetectionContribution, ...]


Detector = Callable[[list[FlowFeatures]], list[DetectionResult]]

FROZEN_BASELINE_SEEDS = (300, 301, 302, 303, 304)
SUPERVISED_TRAINING_SEEDS = (700, 701, 702, 703, 704)
QUICK_EVALUATION_SEEDS = (300,)
QUICK_EVALUATION_CASE_NAMES = (
    "baseline_balanced",
    "jitter_high",
    "benign_burst_sleep",
    "lower_event_counts",
    "time_size_jitter_high",
)
OPERATING_POINT_THRESHOLDS = (2.2, 2.8)
STATISTICAL_REFERENCE_SEED_OFFSET = 10_000


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    name: str
    description: str
    config: SyntheticTrafficConfig


@dataclass(frozen=True, slots=True)
class PredictionRecord:
    case_name: str
    seed: int
    scenario_name: str | None
    true_label: str
    predicted_label: str
    score: float
    event_count: int
    triggered_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScenarioDetectionRate:
    scenario_name: str
    total_flows: int
    true_beacon_flows: int
    predicted_beacon_flows: int
    detection_rate: float


@dataclass(frozen=True, slots=True)
class CaseMetrics:
    case_name: str
    metrics: ClassificationMetrics
    total_flows: int


@dataclass(frozen=True, slots=True)
class MultiSeedEvaluationSummary:
    seed_summaries: tuple[EvaluationSummary, ...]
    combined_summary: EvaluationSummary
    metric_spread: MetricSpread


@dataclass(frozen=True, slots=True)
class ThresholdSweepResult:
    prediction_threshold: float
    summary: EvaluationSummary


@dataclass(frozen=True, slots=True)
class MultiSeedThresholdResult:
    prediction_threshold: float
    summary: MultiSeedEvaluationSummary


@dataclass(frozen=True, slots=True)
class EvaluationSummary:
    records: tuple[PredictionRecord, ...]
    overall_metrics: ClassificationMetrics
    per_case_metrics: tuple[CaseMetrics, ...]
    per_scenario_rates: tuple[ScenarioDetectionRate, ...]
    failure_records: tuple[PredictionRecord, ...]
    near_threshold_records: tuple[PredictionRecord, ...]


def build_default_evaluation_grid(
    start_time: datetime | None = None,
) -> list[EvaluationCase]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=100,
        normal_event_count=90,
        normal_flow_count=14,
        beacon_event_count=18,
        mean_interval_seconds=60.0,
        duration_seconds=5400,
    )

    return [
        EvaluationCase(
            name="baseline_balanced",
            description="Balanced synthetic baseline with all beacon scenarios.",
            config=base,
        ),
        EvaluationCase(
            name="jitter_medium",
            description="Moderate timing jitter on jittered scenarios.",
            config=replace(base, seed=101, jitter_fraction=0.55),
        ),
        EvaluationCase(
            name="jitter_high",
            description="High timing jitter that should pressure periodic rules.",
            config=replace(base, seed=102, jitter_fraction=0.90),
        ),
        EvaluationCase(
            name="bursty_weak",
            description="Weaker burst structure with smaller bursts and shorter sleeps.",
            config=replace(
                base,
                seed=103,
                burst_size_min=2,
                burst_size_max=3,
                sleep_duration_seconds=45.0,
            ),
        ),
        EvaluationCase(
            name="lower_event_counts",
            description="Fewer events per beacon flow, close to the detector minimum.",
            config=replace(base, seed=104, beacon_event_count=5, normal_event_count=70),
        ),
        EvaluationCase(
            name="class_imbalance",
            description="More normal traffic relative to beacon traffic.",
            config=replace(
                base,
                seed=105,
                normal_event_count=220,
                normal_flow_count=28,
                beacon_event_count=8,
            ),
        ),
        EvaluationCase(
            name="variable_normal",
            description="More variable benign sizes and longer irregular gaps.",
            config=replace(
                base,
                seed=106,
                normal_event_count=160,
                normal_flow_count=20,
                normal_size_min_bytes=40,
                normal_size_max_bytes=1800,
                normal_max_gap_seconds=480.0,
            ),
        ),
        EvaluationCase(
            name="benign_periodic_polling",
            description="Benign keepalive and telemetry flows with moderate periodicity.",
            config=replace(
                base,
                seed=108,
                normal_event_count=180,
                normal_flow_count=24,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=12,
                normal_profiles=(
                    NormalTrafficProfile.KEEPALIVE,
                    NormalTrafficProfile.TELEMETRY,
                ),
                beacon_event_count=12,
            ),
        ),
        EvaluationCase(
            name="benign_jittered_polling",
            description="Benign API polling and telemetry with jittered repeated destinations.",
            config=replace(
                base,
                seed=109,
                normal_event_count=180,
                normal_flow_count=24,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=12,
                normal_profiles=(
                    NormalTrafficProfile.API_POLLING,
                    NormalTrafficProfile.TELEMETRY,
                ),
                beacon_event_count=12,
            ),
        ),
        EvaluationCase(
            name="benign_burst_sleep",
            description="Benign sessions with burst/sleep behaviour.",
            config=replace(
                base,
                seed=110,
                normal_event_count=180,
                normal_flow_count=24,
                normal_events_per_flow_min=6,
                normal_events_per_flow_max=12,
                normal_profiles=(NormalTrafficProfile.BURSTY_SESSION,),
                beacon_event_count=12,
            ),
        ),
        EvaluationCase(
            name="benign_stable_size_repetition",
            description="Benign repeated flows with stable-ish sizes.",
            config=replace(
                base,
                seed=111,
                normal_event_count=180,
                normal_flow_count=24,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=12,
                normal_profiles=(
                    NormalTrafficProfile.KEEPALIVE,
                    NormalTrafficProfile.SOFTWARE_UPDATE,
                ),
                beacon_event_count=12,
            ),
        ),
        EvaluationCase(
            name="hard_class_imbalance",
            description="Class imbalance with harder benign polling profiles.",
            config=replace(
                base,
                seed=112,
                normal_event_count=320,
                normal_flow_count=42,
                normal_events_per_flow_min=5,
                normal_events_per_flow_max=12,
                normal_profiles=(
                    NormalTrafficProfile.KEEPALIVE,
                    NormalTrafficProfile.TELEMETRY,
                    NormalTrafficProfile.API_POLLING,
                    NormalTrafficProfile.BURSTY_SESSION,
                ),
                beacon_event_count=8,
            ),
        ),
        EvaluationCase(
            name="time_size_jitter_high",
            description="Higher timing and size jitter for time+size jittered beacons.",
            config=replace(
                base,
                seed=107,
                jitter_fraction=0.75,
                beacon_size_jitter_fraction=0.75,
            ),
        ),
    ]


def build_quick_evaluation_grid(
    start_time: datetime | None = None,
) -> list[EvaluationCase]:
    """Small explicit grid for fast detector sanity checks.

    This does not replace the hardened grid. It is intentionally narrow so
    anomaly experiments can be checked without a full multi-seed run.
    """

    cases = build_default_evaluation_grid(start_time=start_time)
    return [case for case in cases if case.name in QUICK_EVALUATION_CASE_NAMES]


def build_multiseed_evaluation_grid(
    seeds: range | list[int] | tuple[int, ...],
    start_time: datetime | None = None,
    template_cases: list[EvaluationCase] | None = None,
) -> list[list[EvaluationCase]]:
    template_cases = template_cases or build_default_evaluation_grid(
        start_time=start_time
    )
    grids: list[list[EvaluationCase]] = []
    for seed in seeds:
        seed_cases: list[EvaluationCase] = []
        for case in template_cases:
            seed_cases.append(
                EvaluationCase(
                    name=case.name,
                    description=case.description,
                    config=replace(case.config, seed=seed),
                )
            )
        grids.append(seed_cases)
    return grids


def evaluate_rule_detector(
    cases: list[EvaluationCase] | None = None,
    thresholds: RuleThresholds | None = None,
    cache_config: FeatureCacheConfig | None = None,
    near_threshold_margin: float = 0.3,
) -> EvaluationSummary:
    thresholds = thresholds or RuleThresholds()
    detector = lambda rows: detect_flow_feature_rows(rows, thresholds=thresholds)
    return evaluate_cases(
        cases or build_default_evaluation_grid(),
        detector=detector,
        decision_threshold=thresholds.prediction_threshold,
        cache_config=cache_config,
        near_threshold_margin=near_threshold_margin,
    )


def evaluate_rule_detector_multi_seed(
    seeds: range | list[int] | tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    thresholds: RuleThresholds | None = None,
    cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> MultiSeedEvaluationSummary:
    thresholds = thresholds or RuleThresholds()
    summaries = [
        evaluate_rule_detector(
            seed_cases,
            thresholds=thresholds,
            cache_config=cache_config,
            near_threshold_margin=near_threshold_margin,
        )
        for seed_cases in build_multiseed_evaluation_grid(
            seeds,
            start_time=start_time,
            template_cases=cases,
        )
    ]
    combined_records = [
        record for summary in summaries for record in summary.records
    ]
    return MultiSeedEvaluationSummary(
        seed_summaries=tuple(summaries),
        combined_summary=summarize_prediction_records(
            combined_records,
            decision_threshold=thresholds.prediction_threshold,
            near_threshold_margin=near_threshold_margin,
        ),
        metric_spread=summarize_metric_spread(
            [summary.overall_metrics for summary in summaries]
        ),
    )


def build_statistical_reference_features(
    seed: int,
    start_time: datetime | None = None,
    cache_config: FeatureCacheConfig | None = None,
) -> list[FlowFeatures]:
    reference_config = _reference_config(seed, start_time=start_time)
    result = get_or_build_feature_rows(
        cache_config=cache_config,
        cache_kind="benign_reference",
        cache_name="all_profiles",
        seed=seed,
        source_config=reference_config,
        build_rows=lambda: _extract_reference_features(reference_config),
    )
    return result.rows


def evaluate_statistical_detector(
    cases: list[EvaluationCase] | None = None,
    config: StatisticalBaselineConfig | None = None,
    reference_seed: int = STATISTICAL_REFERENCE_SEED_OFFSET,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> EvaluationSummary:
    reference_features = build_statistical_reference_features(
        seed=reference_seed,
        start_time=start_time,
        cache_config=cache_config,
    )
    model = fit_statistical_baseline(reference_features, config=config)
    detector = lambda rows: detect_flow_feature_rows_statistical(rows, model=model)
    return evaluate_cases(
        cases or build_default_evaluation_grid(start_time=start_time),
        detector=detector,
        decision_threshold=model.prediction_threshold,
        cache_config=cache_config,
        near_threshold_margin=near_threshold_margin,
    )


def evaluate_statistical_detector_multi_seed(
    seeds: range | list[int] | tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    config: StatisticalBaselineConfig | None = None,
    cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> MultiSeedEvaluationSummary:
    summaries: list[EvaluationSummary] = []
    fitted_thresholds: list[float] = []
    for seed, seed_cases in zip(
        seeds,
        build_multiseed_evaluation_grid(
            seeds,
            start_time=start_time,
            template_cases=cases,
        ),
    ):
        reference_features = build_statistical_reference_features(
            seed=seed + STATISTICAL_REFERENCE_SEED_OFFSET,
            start_time=start_time,
            cache_config=cache_config,
        )
        model = fit_statistical_baseline(reference_features, config=config)
        detector = lambda rows, model=model: detect_flow_feature_rows_statistical(
            rows,
            model=model,
        )
        fitted_thresholds.append(model.prediction_threshold)
        summaries.append(
            evaluate_cases(
                cases=seed_cases,
                detector=detector,
                decision_threshold=model.prediction_threshold,
                cache_config=cache_config,
                near_threshold_margin=near_threshold_margin,
            )
        )

    combined_records = [
        record for summary in summaries for record in summary.records
    ]
    combined_threshold = (
        sum(fitted_thresholds) / len(fitted_thresholds)
        if fitted_thresholds
        else 0.0
    )
    return MultiSeedEvaluationSummary(
        seed_summaries=tuple(summaries),
        combined_summary=summarize_prediction_records(
            combined_records,
            decision_threshold=combined_threshold,
            near_threshold_margin=near_threshold_margin,
        ),
        metric_spread=summarize_metric_spread(
            [summary.overall_metrics for summary in summaries]
        ),
    )


def evaluate_anomaly_detector(
    detector_type: AnomalyDetectorType,
    cases: list[EvaluationCase] | None = None,
    config: AnomalyDetectorConfig | None = None,
    reference_seed: int = STATISTICAL_REFERENCE_SEED_OFFSET,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> EvaluationSummary:
    reference_features = build_statistical_reference_features(
        seed=reference_seed,
        start_time=start_time,
        cache_config=cache_config,
    )
    model = fit_anomaly_detector(
        reference_features,
        detector_type=detector_type,
        config=config,
    )
    detector = lambda rows: detect_flow_feature_rows_anomaly(rows, model=model)
    return evaluate_cases(
        cases or build_default_evaluation_grid(start_time=start_time),
        detector=detector,
        decision_threshold=model.prediction_threshold,
        cache_config=cache_config,
        near_threshold_margin=near_threshold_margin,
    )


def evaluate_anomaly_detector_multi_seed(
    detector_type: AnomalyDetectorType,
    seeds: range | list[int] | tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    config: AnomalyDetectorConfig | None = None,
    cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> MultiSeedEvaluationSummary:
    summaries: list[EvaluationSummary] = []
    for seed, seed_cases in zip(
        seeds,
        build_multiseed_evaluation_grid(
            seeds,
            start_time=start_time,
            template_cases=cases,
        ),
    ):
        summaries.append(
            evaluate_anomaly_detector(
                detector_type=detector_type,
                cases=seed_cases,
                config=config,
                reference_seed=seed + STATISTICAL_REFERENCE_SEED_OFFSET,
                cache_config=cache_config,
                start_time=start_time,
                near_threshold_margin=near_threshold_margin,
            )
        )

    combined_records = [
        record for summary in summaries for record in summary.records
    ]
    return MultiSeedEvaluationSummary(
        seed_summaries=tuple(summaries),
        combined_summary=summarize_prediction_records(
            combined_records,
            decision_threshold=0.0,
            near_threshold_margin=near_threshold_margin,
        ),
        metric_spread=summarize_metric_spread(
            [summary.overall_metrics for summary in summaries]
        ),
    )


def build_supervised_training_features(
    training_seeds: range | list[int] | tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    training_cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
) -> list[FlowFeatures]:
    rows: list[FlowFeatures] = []
    for seed_cases in build_multiseed_evaluation_grid(
        training_seeds,
        start_time=start_time,
        template_cases=training_cases,
    ):
        for case in seed_cases:
            rows.extend(_training_case_feature_rows(case, cache_config=cache_config))
    return rows


def build_case_feature_rows(
    case: EvaluationCase,
    cache_config: FeatureCacheConfig | None = None,
) -> list[FlowFeatures]:
    return _case_feature_rows(case, cache_config=cache_config)


def evaluate_supervised_detector(
    detector_type: SupervisedDetectorType,
    cases: list[EvaluationCase] | None = None,
    config: SupervisedDetectorConfig | None = None,
    training_seeds: range | list[int] | tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    training_cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.1,
) -> EvaluationSummary:
    config = config or SupervisedDetectorConfig()
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        training_cases=training_cases,
        cache_config=cache_config,
        start_time=start_time,
    )
    model = fit_supervised_detector(
        training_features,
        detector_type=detector_type,
        config=config,
    )
    detector = lambda rows: detect_flow_feature_rows_supervised(rows, model=model)
    return evaluate_cases(
        cases or build_default_evaluation_grid(start_time=start_time),
        detector=detector,
        decision_threshold=config.prediction_threshold,
        cache_config=cache_config,
        near_threshold_margin=near_threshold_margin,
    )


def evaluate_supervised_detector_multi_seed(
    detector_type: SupervisedDetectorType,
    seeds: range | list[int] | tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    config: SupervisedDetectorConfig | None = None,
    cases: list[EvaluationCase] | None = None,
    training_seeds: range | list[int] | tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    training_cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.1,
) -> MultiSeedEvaluationSummary:
    config = config or SupervisedDetectorConfig()
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        training_cases=training_cases,
        cache_config=cache_config,
        start_time=start_time,
    )
    model = fit_supervised_detector(
        training_features,
        detector_type=detector_type,
        config=config,
    )
    detector = lambda rows: detect_flow_feature_rows_supervised(rows, model=model)
    summaries = [
        evaluate_cases(
            seed_cases,
            detector=detector,
            decision_threshold=config.prediction_threshold,
            cache_config=cache_config,
            near_threshold_margin=near_threshold_margin,
        )
        for seed_cases in build_multiseed_evaluation_grid(
            seeds,
            start_time=start_time,
            template_cases=cases,
        )
    ]

    combined_records = [
        record for summary in summaries for record in summary.records
    ]
    return MultiSeedEvaluationSummary(
        seed_summaries=tuple(summaries),
        combined_summary=summarize_prediction_records(
            combined_records,
            decision_threshold=config.prediction_threshold,
            near_threshold_margin=near_threshold_margin,
        ),
        metric_spread=summarize_metric_spread(
            [summary.overall_metrics for summary in summaries]
        ),
    )


def sweep_prediction_thresholds(
    thresholds_to_try: list[float],
    cases: list[EvaluationCase] | None = None,
    base_thresholds: RuleThresholds | None = None,
    cache_config: FeatureCacheConfig | None = None,
) -> list[ThresholdSweepResult]:
    base_thresholds = base_thresholds or RuleThresholds()
    return [
        ThresholdSweepResult(
            prediction_threshold=prediction_threshold,
            summary=evaluate_rule_detector(
                cases=cases,
                thresholds=replace(
                    base_thresholds,
                    prediction_threshold=prediction_threshold,
                ),
                cache_config=cache_config,
            ),
        )
        for prediction_threshold in thresholds_to_try
    ]


def sweep_prediction_thresholds_multi_seed(
    thresholds_to_try: list[float] | tuple[float, ...] = OPERATING_POINT_THRESHOLDS,
    seeds: range | list[int] | tuple[int, ...] = FROZEN_BASELINE_SEEDS,
    base_thresholds: RuleThresholds | None = None,
    cases: list[EvaluationCase] | None = None,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
    near_threshold_margin: float = 0.3,
) -> list[MultiSeedThresholdResult]:
    base_thresholds = base_thresholds or RuleThresholds()
    return [
        MultiSeedThresholdResult(
            prediction_threshold=prediction_threshold,
            summary=evaluate_rule_detector_multi_seed(
                seeds=seeds,
                thresholds=replace(
                    base_thresholds,
                    prediction_threshold=prediction_threshold,
                ),
                cases=cases,
                cache_config=cache_config,
                start_time=start_time,
                near_threshold_margin=near_threshold_margin,
            ),
        )
        for prediction_threshold in thresholds_to_try
    ]


def evaluate_cases(
    cases: list[EvaluationCase],
    detector: Detector,
    decision_threshold: float,
    cache_config: FeatureCacheConfig | None = None,
    near_threshold_margin: float = 0.3,
) -> EvaluationSummary:
    records: list[PredictionRecord] = []
    for case in cases:
        records.extend(_evaluate_case(case, detector, cache_config=cache_config))

    return summarize_prediction_records(
        records,
        decision_threshold=decision_threshold,
        near_threshold_margin=near_threshold_margin,
    )


def summarize_prediction_records(
    records: list[PredictionRecord] | tuple[PredictionRecord, ...],
    decision_threshold: float,
    near_threshold_margin: float = 0.3,
) -> EvaluationSummary:
    records = list(records)
    true_labels = [record.true_label for record in records]
    predicted_labels = [record.predicted_label for record in records]
    metrics = calculate_classification_metrics(true_labels, predicted_labels)
    failures = tuple(
        record for record in records if record.true_label != record.predicted_label
    )
    near_threshold = tuple(
        record
        for record in records
        if abs(record.score - decision_threshold) <= near_threshold_margin
    )

    return EvaluationSummary(
        records=tuple(records),
        overall_metrics=metrics,
        per_case_metrics=tuple(_calculate_per_case_metrics(records)),
        per_scenario_rates=tuple(_calculate_per_scenario_rates(records)),
        failure_records=failures,
        near_threshold_records=near_threshold,
    )


def _evaluate_case(
    case: EvaluationCase,
    detector: Detector,
    cache_config: FeatureCacheConfig | None = None,
) -> list[PredictionRecord]:
    feature_rows = _case_feature_rows(case, cache_config=cache_config)
    feature_by_key = {row.flow_key: row for row in feature_rows}
    results = detector(feature_rows)

    records: list[PredictionRecord] = []
    for result in results:
        features = feature_by_key[result.flow_key]
        records.append(
            PredictionRecord(
                case_name=case.name,
                seed=case.config.seed,
                scenario_name=result.scenario_name,
                true_label=result.true_label,
                predicted_label=result.predicted_label,
                score=result.score,
                event_count=features.event_count,
                triggered_rules=tuple(
                    contribution.rule_name
                    for contribution in result.contributions
                    if contribution.fired and contribution.score > 0
                ),
            )
        )
    return records


def _case_feature_rows(
    case: EvaluationCase,
    cache_config: FeatureCacheConfig | None = None,
) -> list[FlowFeatures]:
    result = get_or_build_feature_rows(
        cache_config=cache_config,
        cache_kind="evaluation_case",
        cache_name=case.name,
        seed=case.config.seed,
        source_config=case.config,
        build_rows=lambda: _extract_case_features(case),
    )
    return result.rows


def _training_case_feature_rows(
    case: EvaluationCase,
    cache_config: FeatureCacheConfig | None = None,
) -> list[FlowFeatures]:
    result = get_or_build_feature_rows(
        cache_config=cache_config,
        cache_kind="supervised_training_case",
        cache_name=case.name,
        seed=case.config.seed,
        source_config=case.config,
        build_rows=lambda: _extract_case_features(case),
    )
    return result.rows


def _extract_case_features(case: EvaluationCase) -> list[FlowFeatures]:
    events = generate_combined_synthetic_dataset(case.config)
    flows = build_flows(events)
    return extract_features_from_flows(flows)


def _reference_config(
    seed: int,
    start_time: datetime | None = None,
) -> SyntheticTrafficConfig:
    return SyntheticTrafficConfig(
        start_time=start_time or datetime(2026, 1, 1, tzinfo=timezone.utc),
        seed=seed,
        normal_event_count=900,
        normal_flow_count=120,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=14,
        duration_seconds=7200,
        normal_profiles=tuple(NormalTrafficProfile),
    )


def _extract_reference_features(config: SyntheticTrafficConfig) -> list[FlowFeatures]:
    events = generate_synthetic_events(config, GenerationScenario.NORMAL)
    return extract_features_from_flows(build_flows(events))


def _calculate_per_scenario_rates(
    records: list[PredictionRecord],
) -> list[ScenarioDetectionRate]:
    scenario_names = sorted({record.scenario_name or "unknown" for record in records})
    rates: list[ScenarioDetectionRate] = []
    for scenario_name in scenario_names:
        scenario_records = [
            record
            for record in records
            if (record.scenario_name or "unknown") == scenario_name
        ]
        true_beacons = [
            record for record in scenario_records if record.true_label == "beacon"
        ]
        predicted_beacons = [
            record for record in scenario_records if record.predicted_label == "beacon"
        ]
        denominator = len(true_beacons) if true_beacons else len(scenario_records)
        detection_rate = len(predicted_beacons) / denominator if denominator else 0.0
        rates.append(
            ScenarioDetectionRate(
                scenario_name=scenario_name,
                total_flows=len(scenario_records),
                true_beacon_flows=len(true_beacons),
                predicted_beacon_flows=len(predicted_beacons),
                detection_rate=detection_rate,
            )
        )
    return rates


def _calculate_per_case_metrics(records: list[PredictionRecord]) -> list[CaseMetrics]:
    case_names = sorted({record.case_name for record in records})
    case_metrics: list[CaseMetrics] = []
    for case_name in case_names:
        case_records = [record for record in records if record.case_name == case_name]
        case_metrics.append(
            CaseMetrics(
                case_name=case_name,
                metrics=calculate_classification_metrics(
                    [record.true_label for record in case_records],
                    [record.predicted_label for record in case_records],
                ),
                total_flows=len(case_records),
            )
        )
    return case_metrics
