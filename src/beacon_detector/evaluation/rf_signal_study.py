from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from beacon_detector.data import (
    NormalTrafficProfile,
    ShortcutOverlapLevel,
    SyntheticTrafficConfig,
)
from beacon_detector.detection import (
    SupervisedDetectorConfig,
    detect_flow_feature_rows_supervised,
    fit_supervised_detector,
)

from .cache import FEATURE_SCHEMA_VERSION, FeatureCacheConfig
from .runner import (
    SUPERVISED_TRAINING_SEEDS,
    EvaluationCase,
    build_case_feature_rows,
    build_default_evaluation_grid,
    build_multiseed_evaluation_grid,
    build_supervised_training_features,
)
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name

RF_SIGNAL_STUDY_SEEDS = (980, 981, 982)
RF_SIGNAL_STUDY_OPERATING_POINTS = (
    ("rf_full_threshold_0p6", "full", 0.6),
    ("rf_full_threshold_0p3", "full", 0.3),
)
EVENT_COUNT_VALUES = (5, 7, 9, 12, 15)
TIMING_JITTER_VALUES = (0.30, 0.50, 0.70, 0.95)
SIZE_JITTER_VALUES = (0.20, 0.40, 0.70, 0.95)
DURATION_MEAN_INTERVAL_VALUES = (35.0, 55.0, 80.0, 120.0)
OVERLAP_LEVEL_VALUES = (
    ShortcutOverlapLevel.LOW,
    ShortcutOverlapLevel.MEDIUM,
    ShortcutOverlapLevel.HIGH,
)
TIMING_SIZE_INTERACTION_VALUES = (
    (0.30, 0.20),
    (0.50, 0.40),
    (0.70, 0.70),
    (0.95, 0.95),
)


@dataclass(frozen=True, slots=True)
class SignalStudyCase:
    factor_name: str
    factor_value: str
    case: EvaluationCase


@dataclass(frozen=True, slots=True)
class SignalStudyProbabilityRecord:
    detector_name: str
    feature_set_name: str
    threshold: float
    factor_name: str
    factor_value: str
    case_name: str
    seed: int
    scenario_name: str | None
    true_label: str
    predicted_label: str
    predicted_probability: float


@dataclass(frozen=True, slots=True)
class SignalStudySummaryRow:
    detector_name: str
    feature_set_name: str
    threshold: float
    factor_name: str
    factor_value: str
    time_size_flow_count: int
    mean_probability: float | None
    median_probability: float | None
    min_probability: float | None
    max_probability: float | None
    detection_rate: float
    false_negative_count: int
    benign_false_positive_rate: float
    benign_false_positive_count: int


@dataclass(frozen=True, slots=True)
class SignalStudyResult:
    summary_rows: tuple[SignalStudySummaryRow, ...]
    probability_records: tuple[SignalStudyProbabilityRecord, ...]


def build_signal_study_base_config(
    start_time: datetime | None = None,
) -> SyntheticTrafficConfig:
    return SyntheticTrafficConfig(
        start_time=start_time or datetime(2026, 1, 1, tzinfo=timezone.utc),
        seed=980,
        normal_event_count=190,
        normal_flow_count=32,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=8,
        beacon_event_count=6,
        mean_interval_seconds=70.0,
        duration_seconds=5400,
        beacon_size_bytes=175,
        beacon_size_jitter_fraction=0.70,
        shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
        time_size_jittered_event_count=5,
        time_size_jittered_mean_interval_seconds=70.0,
        time_size_jittered_jitter_fraction=0.95,
        time_size_jittered_size_jitter_fraction=0.95,
        normal_profiles=(
            NormalTrafficProfile.KEEPALIVE,
            NormalTrafficProfile.TELEMETRY,
            NormalTrafficProfile.API_POLLING,
            NormalTrafficProfile.BURSTY_SESSION,
            NormalTrafficProfile.SOFTWARE_UPDATE,
        ),
    )


def build_time_size_signal_study_cases(
    start_time: datetime | None = None,
) -> list[SignalStudyCase]:
    base = build_signal_study_base_config(start_time=start_time)
    cases: list[SignalStudyCase] = []

    for event_count in EVENT_COUNT_VALUES:
        cases.append(
            _study_case(
                "event_count",
                str(event_count),
                replace(base, time_size_jittered_event_count=event_count),
            )
        )
    for jitter in TIMING_JITTER_VALUES:
        cases.append(
            _study_case(
                "timing_jitter",
                f"{jitter:g}",
                replace(base, time_size_jittered_jitter_fraction=jitter),
            )
        )
    for jitter in SIZE_JITTER_VALUES:
        cases.append(
            _study_case(
                "size_jitter",
                f"{jitter:g}",
                replace(base, time_size_jittered_size_jitter_fraction=jitter),
            )
        )
    for mean_interval in DURATION_MEAN_INTERVAL_VALUES:
        cases.append(
            _study_case(
                "duration_mean_interval",
                f"{mean_interval:g}",
                replace(base, time_size_jittered_mean_interval_seconds=mean_interval),
            )
        )
    for overlap_level in OVERLAP_LEVEL_VALUES:
        cases.append(
            _study_case(
                "benign_overlap",
                overlap_level.value,
                replace(base, shortcut_overlap_level=overlap_level),
            )
        )
    for timing_jitter, size_jitter in TIMING_SIZE_INTERACTION_VALUES:
        cases.append(
            _study_case(
                "timing_size_interaction",
                f"timing={timing_jitter:g};size={size_jitter:g}",
                replace(
                    base,
                    time_size_jittered_jitter_fraction=timing_jitter,
                    time_size_jittered_size_jitter_fraction=size_jitter,
                ),
            )
        )

    return cases


def run_rf_time_size_signal_study(
    *,
    study_cases: list[SignalStudyCase] | None = None,
    training_cases: list[EvaluationCase] | None = None,
    seeds: tuple[int, ...] = RF_SIGNAL_STUDY_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> SignalStudyResult:
    study_cases = study_cases or build_time_size_signal_study_cases()
    training_cases = training_cases or build_default_evaluation_grid()
    records: list[SignalStudyProbabilityRecord] = []

    for detector_name, feature_set_name, threshold in RF_SIGNAL_STUDY_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        model = _fit_rf_model(
            config=config,
            training_cases=training_cases,
            training_seeds=training_seeds,
            cache_config=cache_config,
        )
        for study_case in study_cases:
            records.extend(
                _score_study_case(
                    detector_name=detector_name,
                    feature_set=feature_set,
                    threshold=threshold,
                    model=model,
                    study_case=study_case,
                    seeds=seeds,
                    cache_config=cache_config,
                )
            )

    return SignalStudyResult(
        summary_rows=tuple(_summarize_signal_records(records)),
        probability_records=tuple(records),
    )


def export_rf_time_size_signal_study_tables(
    *,
    output_dir: str | Path,
    result: SignalStudyResult,
    study_cases: list[SignalStudyCase],
    seeds: tuple[int, ...] = RF_SIGNAL_STUDY_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return [
        _write_summary(output_path, result),
        _write_probabilities(output_path, result),
        _write_metadata(
            output_path,
            study_cases=study_cases,
            seeds=seeds,
            training_seeds=training_seeds,
        ),
    ]


def _study_case(
    factor_name: str,
    factor_value: str,
    config: SyntheticTrafficConfig,
) -> SignalStudyCase:
    case_name = f"signal_{factor_name}_{_safe_name(factor_value)}"
    return SignalStudyCase(
        factor_name=factor_name,
        factor_value=factor_value,
        case=EvaluationCase(
            name=case_name,
            description=f"Signal study case varying {factor_name}={factor_value}.",
            config=config,
        ),
    )


def _fit_rf_model(
    *,
    config: SupervisedDetectorConfig,
    training_cases: list[EvaluationCase],
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
):
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        training_cases=training_cases,
        cache_config=cache_config,
    )
    return fit_supervised_detector(
        training_features,
        detector_type="random_forest",
        config=config,
    )


def _score_study_case(
    *,
    detector_name: str,
    feature_set: SupervisedFeatureSet,
    threshold: float,
    model,
    study_case: SignalStudyCase,
    seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[SignalStudyProbabilityRecord]:
    records: list[SignalStudyProbabilityRecord] = []
    for seed_cases in build_multiseed_evaluation_grid(
        seeds,
        template_cases=[study_case.case],
    ):
        case = seed_cases[0]
        rows = build_case_feature_rows(case, cache_config=cache_config)
        results = detect_flow_feature_rows_supervised(rows, model=model)
        for result in results:
            records.append(
                SignalStudyProbabilityRecord(
                    detector_name=detector_name,
                    feature_set_name=feature_set.name,
                    threshold=threshold,
                    factor_name=study_case.factor_name,
                    factor_value=study_case.factor_value,
                    case_name=case.name,
                    seed=case.config.seed,
                    scenario_name=result.scenario_name,
                    true_label=result.true_label,
                    predicted_label=result.predicted_label,
                    predicted_probability=result.score,
                )
            )
    return records


def _summarize_signal_records(
    records: list[SignalStudyProbabilityRecord],
) -> list[SignalStudySummaryRow]:
    keys = sorted(
        {
            (
                record.detector_name,
                record.feature_set_name,
                record.threshold,
                record.factor_name,
                record.factor_value,
            )
            for record in records
        }
    )
    rows: list[SignalStudySummaryRow] = []
    for detector_name, feature_set_name, threshold, factor_name, factor_value in keys:
        group = [
            record
            for record in records
            if record.detector_name == detector_name
            and record.feature_set_name == feature_set_name
            and record.threshold == threshold
            and record.factor_name == factor_name
            and record.factor_value == factor_value
        ]
        time_size = [
            record
            for record in group
            if record.scenario_name == "time_size_jittered"
        ]
        benign = [record for record in group if record.true_label == "benign"]
        probabilities = [record.predicted_probability for record in time_size]
        detected = [
            record for record in time_size if record.predicted_label == "beacon"
        ]
        false_positives = [
            record for record in benign if record.predicted_label == "beacon"
        ]
        rows.append(
            SignalStudySummaryRow(
                detector_name=detector_name,
                feature_set_name=feature_set_name,
                threshold=threshold,
                factor_name=factor_name,
                factor_value=factor_value,
                time_size_flow_count=len(time_size),
                mean_probability=_mean(probabilities),
                median_probability=_median(probabilities),
                min_probability=min(probabilities) if probabilities else None,
                max_probability=max(probabilities) if probabilities else None,
                detection_rate=len(detected) / len(time_size) if time_size else 0.0,
                false_negative_count=len(time_size) - len(detected),
                benign_false_positive_rate=(
                    len(false_positives) / len(benign) if benign else 0.0
                ),
                benign_false_positive_count=len(false_positives),
            )
        )
    return rows


def _write_summary(output_dir: Path, result: SignalStudyResult) -> Path:
    path = output_dir / "rf_time_size_signal_study_summary.csv"
    rows = [asdict(row) for row in result.summary_rows]
    _write_csv(path, rows)
    return path


def _write_probabilities(output_dir: Path, result: SignalStudyResult) -> Path:
    path = output_dir / "rf_time_size_signal_study_probabilities.csv"
    rows = [asdict(record) for record in result.probability_records]
    _write_csv(path, rows)
    return path


def _write_metadata(
    output_dir: Path,
    *,
    study_cases: list[SignalStudyCase],
    seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "rf_time_size_signal_study_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "purpose": (
            "Controlled one-factor-at-a-time signal study for hard "
            "time_size_jittered RF confidence collapse."
        ),
        "operating_points": [
            {
                "detector_name": detector_name,
                "feature_set": feature_set,
                "threshold": threshold,
            }
            for detector_name, feature_set, threshold in RF_SIGNAL_STUDY_OPERATING_POINTS
        ],
        "seed_list": list(seeds),
        "training_seed_list": list(training_seeds),
        "factor_values": _factor_values(study_cases),
        "cases": [
            {
                "case_name": study_case.case.name,
                "factor_name": study_case.factor_name,
                "factor_value": study_case.factor_value,
                **_study_knobs(study_case.case.config),
            }
            for study_case in study_cases
        ],
        "outputs": [
            "rf_time_size_signal_study_summary.csv",
            "rf_time_size_signal_study_probabilities.csv",
            "rf_time_size_signal_study_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _factor_values(study_cases: list[SignalStudyCase]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for study_case in study_cases:
        values.setdefault(study_case.factor_name, [])
        if study_case.factor_value not in values[study_case.factor_name]:
            values[study_case.factor_name].append(study_case.factor_value)
    return values


def _study_knobs(config: SyntheticTrafficConfig) -> dict[str, str | int | float]:
    return {
        "time_size_jittered_event_count": config.time_size_jittered_event_count or 0,
        "time_size_jittered_mean_interval_seconds": (
            config.time_size_jittered_mean_interval_seconds or 0.0
        ),
        "time_size_jittered_jitter_fraction": (
            config.time_size_jittered_jitter_fraction or 0.0
        ),
        "time_size_jittered_size_jitter_fraction": (
            config.time_size_jittered_size_jitter_fraction or 0.0
        ),
        "shortcut_overlap_level": ShortcutOverlapLevel(
            config.shortcut_overlap_level
        ).value,
    }


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    return float(median(values))


def _safe_name(value: str) -> str:
    return "".join(
        character if character.isalnum() else "_"
        for character in value
    ).strip("_")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
