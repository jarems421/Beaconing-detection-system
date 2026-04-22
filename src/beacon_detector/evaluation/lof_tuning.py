from __future__ import annotations

from dataclasses import dataclass, replace

from beacon_detector.detection import (
    LOCAL_OUTLIER_FACTOR_NAME,
    AnomalyDetectorConfig,
)

from .cache import FeatureCacheConfig
from .runner import (
    QUICK_EVALUATION_SEEDS,
    EvaluationCase,
    MultiSeedEvaluationSummary,
    evaluate_anomaly_detector_multi_seed,
)

DEFAULT_LOF_NEIGHBOR_VALUES = (10, 20, 35, 50)
DEFAULT_LOF_CONTAMINATION_VALUES = (0.02, 0.03, 0.05)


@dataclass(frozen=True, slots=True)
class LofTuningCandidate:
    name: str
    config: AnomalyDetectorConfig


@dataclass(frozen=True, slots=True)
class LofTuningResult:
    candidate: LofTuningCandidate
    summary: MultiSeedEvaluationSummary


def build_small_lof_tuning_grid(
    *,
    base_config: AnomalyDetectorConfig | None = None,
    neighbor_values: tuple[int, ...] = DEFAULT_LOF_NEIGHBOR_VALUES,
    contamination_values: tuple[float, ...] = DEFAULT_LOF_CONTAMINATION_VALUES,
) -> list[LofTuningCandidate]:
    """Build a deliberately small LOF grid.

    The grid is intentionally limited to the two most meaningful LOF knobs for
    this project. Feature subset changes are skipped here so this does not turn
    into a broad anomaly-model search.
    """

    base_config = base_config or AnomalyDetectorConfig()
    candidates: list[LofTuningCandidate] = []
    for neighbors in neighbor_values:
        for contamination in contamination_values:
            config = replace(
                base_config,
                lof_neighbors=neighbors,
                contamination=contamination,
            )
            candidates.append(
                LofTuningCandidate(
                    name=lof_candidate_name(config),
                    config=config,
                )
            )
    return candidates


def run_lof_tuning_grid(
    *,
    candidates: list[LofTuningCandidate],
    cases: list[EvaluationCase],
    seeds: tuple[int, ...] = QUICK_EVALUATION_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> list[LofTuningResult]:
    return [
        LofTuningResult(
            candidate=candidate,
            summary=evaluate_anomaly_detector_multi_seed(
                "local_outlier_factor",
                seeds=seeds,
                config=candidate.config,
                cases=cases,
                cache_config=cache_config,
            ),
        )
        for candidate in candidates
    ]


def select_best_lof_candidate(results: list[LofTuningResult]) -> LofTuningResult:
    """Select by F1 first, then precision, then recall, then lower FPR."""

    if not results:
        raise ValueError("At least one LOF tuning result is required.")

    return max(
        results,
        key=lambda result: (
            result.summary.combined_summary.overall_metrics.f1_score,
            result.summary.combined_summary.overall_metrics.precision,
            result.summary.combined_summary.overall_metrics.recall,
            -result.summary.combined_summary.overall_metrics.false_positive_rate,
        ),
    )


def lof_candidate_name(config: AnomalyDetectorConfig) -> str:
    contamination = str(config.contamination).replace(".", "p")
    return (
        f"{LOCAL_OUTLIER_FACTOR_NAME}_"
        f"n{config.lof_neighbors}_"
        f"c{contamination}"
    )


def lof_operating_point(config: AnomalyDetectorConfig) -> str:
    return (
        f"lof_neighbors={config.lof_neighbors};"
        f"contamination={config.contamination:g}"
    )
