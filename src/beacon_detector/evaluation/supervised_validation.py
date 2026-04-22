from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone

from beacon_detector.data import NormalTrafficProfile, SyntheticTrafficConfig
from beacon_detector.detection import (
    SupervisedDetectorConfig,
    SupervisedDetectorType,
    detect_flow_feature_rows_supervised,
    fit_supervised_detector,
)
from beacon_detector.features import FlowFeatures

from .cache import FeatureCacheConfig
from .runner import (
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    EvaluationSummary,
    MultiSeedEvaluationSummary,
    build_multiseed_evaluation_grid,
    build_supervised_training_features,
    evaluate_cases,
    summarize_metric_spread,
    summarize_prediction_records,
)

SUPERVISED_HOLDOUT_EVALUATION_SEEDS = (800, 801, 802)


@dataclass(frozen=True, slots=True)
class SupervisedHoldoutExperiment:
    name: str
    description: str
    training_cases: tuple[EvaluationCase, ...]
    evaluation_cases: tuple[EvaluationCase, ...]
    excluded_training_scenarios: tuple[str, ...] = ()
    excluded_training_profiles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SupervisedHoldoutResult:
    experiment: SupervisedHoldoutExperiment
    detector_type: SupervisedDetectorType
    summary: MultiSeedEvaluationSummary
    training_flow_count: int
    training_beacon_flow_count: int
    training_benign_flow_count: int


def build_supervised_holdout_suite(
    start_time: datetime | None = None,
) -> list[SupervisedHoldoutExperiment]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=700,
        normal_event_count=180,
        normal_flow_count=24,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=12,
        beacon_event_count=14,
        mean_interval_seconds=60.0,
        duration_seconds=5400,
    )

    benign_profiles_without_bursty = tuple(
        profile
        for profile in NormalTrafficProfile
        if profile is not NormalTrafficProfile.BURSTY_SESSION
    )

    return [
        SupervisedHoldoutExperiment(
            name="jitter_regime_holdout",
            description="Train on moderate jitter and evaluate on high timing jitter.",
            training_cases=(
                EvaluationCase(
                    "train_moderate_jitter",
                    "Moderate jitter training regime.",
                    replace(base, jitter_fraction=0.35, beacon_size_jitter_fraction=0.25),
                ),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "eval_high_jitter",
                    "High jitter evaluation regime.",
                    replace(base, jitter_fraction=0.95, beacon_size_jitter_fraction=0.25),
                ),
            ),
        ),
        SupervisedHoldoutExperiment(
            name="low_event_count_holdout",
            description="Train on richer beacon flows and evaluate on low-event beacons.",
            training_cases=(
                EvaluationCase(
                    "train_standard_event_counts",
                    "Training flows with 12-18 beacon events.",
                    replace(base, beacon_event_count=14, normal_event_count=180),
                ),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "eval_low_event_counts",
                    "Evaluation flows with very few beacon events.",
                    replace(base, beacon_event_count=5, normal_event_count=180),
                ),
            ),
        ),
        SupervisedHoldoutExperiment(
            name="benign_bursty_profile_holdout",
            description="Train without benign bursty sessions and evaluate on them.",
            training_cases=(
                EvaluationCase(
                    "train_without_bursty_benign",
                    "Training benign profiles exclude normal_bursty_session.",
                    replace(base, normal_profiles=benign_profiles_without_bursty),
                ),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "eval_bursty_benign_only",
                    "Evaluation benign traffic is normal_bursty_session.",
                    replace(
                        base,
                        normal_profiles=(NormalTrafficProfile.BURSTY_SESSION,),
                        normal_event_count=180,
                        normal_flow_count=24,
                    ),
                ),
            ),
            excluded_training_profiles=(NormalTrafficProfile.BURSTY_SESSION.value,),
        ),
        SupervisedHoldoutExperiment(
            name="time_size_jittered_scenario_holdout",
            description="Train without time+size jittered beacons and evaluate on harder variants.",
            training_cases=(
                EvaluationCase(
                    "train_without_time_size_jittered",
                    "Training excludes the time_size_jittered beacon scenario.",
                    replace(base, jitter_fraction=0.45, beacon_size_jitter_fraction=0.25),
                ),
            ),
            evaluation_cases=(
                EvaluationCase(
                    "eval_high_time_size_jittered",
                    "Evaluation includes high time and size jitter.",
                    replace(base, jitter_fraction=0.85, beacon_size_jitter_fraction=0.85),
                ),
            ),
            excluded_training_scenarios=("time_size_jittered",),
        ),
    ]


def evaluate_supervised_holdout_experiment(
    experiment: SupervisedHoldoutExperiment,
    detector_type: SupervisedDetectorType,
    config: SupervisedDetectorConfig | None = None,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
) -> SupervisedHoldoutResult:
    config = config or SupervisedDetectorConfig()
    training_features = _build_holdout_training_features(
        experiment=experiment,
        training_seeds=training_seeds,
        cache_config=cache_config,
        start_time=start_time,
    )
    model = fit_supervised_detector(
        training_features,
        detector_type=detector_type,
        config=config,
    )
    def detector(rows):
        return detect_flow_feature_rows_supervised(rows, model=model)

    summaries: list[EvaluationSummary] = []
    for seed_cases in build_multiseed_evaluation_grid(
        evaluation_seeds,
        start_time=start_time,
        template_cases=list(experiment.evaluation_cases),
    ):
        summaries.append(
            evaluate_cases(
                seed_cases,
                detector=detector,
                decision_threshold=config.prediction_threshold,
                cache_config=cache_config,
                near_threshold_margin=0.1,
            )
        )

    combined_records = [
        record for summary in summaries for record in summary.records
    ]
    beacon_count = sum(1 for row in training_features if row.label == "beacon")
    benign_count = sum(1 for row in training_features if row.label == "benign")
    return SupervisedHoldoutResult(
        experiment=experiment,
        detector_type=detector_type,
        summary=MultiSeedEvaluationSummary(
            seed_summaries=tuple(summaries),
            combined_summary=summarize_prediction_records(
                combined_records,
                decision_threshold=config.prediction_threshold,
                near_threshold_margin=0.1,
            ),
            metric_spread=summarize_metric_spread(
                [summary.overall_metrics for summary in summaries]
            ),
        ),
        training_flow_count=len(training_features),
        training_beacon_flow_count=beacon_count,
        training_benign_flow_count=benign_count,
    )


def evaluate_supervised_holdout_suite(
    detector_type: SupervisedDetectorType,
    experiments: list[SupervisedHoldoutExperiment] | None = None,
    config: SupervisedDetectorConfig | None = None,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    evaluation_seeds: tuple[int, ...] = SUPERVISED_HOLDOUT_EVALUATION_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
    start_time: datetime | None = None,
) -> list[SupervisedHoldoutResult]:
    experiments = experiments or build_supervised_holdout_suite(start_time=start_time)
    return [
        evaluate_supervised_holdout_experiment(
            experiment=experiment,
            detector_type=detector_type,
            config=config,
            training_seeds=training_seeds,
            evaluation_seeds=evaluation_seeds,
            cache_config=cache_config,
            start_time=start_time,
        )
        for experiment in experiments
    ]


def _build_holdout_training_features(
    *,
    experiment: SupervisedHoldoutExperiment,
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
    start_time: datetime | None,
) -> list[FlowFeatures]:
    rows: list[FlowFeatures] = []
    rows.extend(
        build_supervised_training_features(
            training_seeds=training_seeds,
            training_cases=list(experiment.training_cases),
            cache_config=cache_config,
            start_time=start_time,
        )
    )

    return [
        row
        for row in rows
        if (row.scenario_name or "") not in experiment.excluded_training_scenarios
        and (row.scenario_name or "") not in experiment.excluded_training_profiles
    ]
