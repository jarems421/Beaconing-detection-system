from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from statistics import median
from typing import Any

from beacon_detector.data import (
    GenerationScenario,
    NormalTrafficProfile,
    ShortcutOverlapLevel,
    SyntheticTrafficConfig,
    generate_synthetic_events,
)
from beacon_detector.detection import (
    AnomalyDetectorConfig,
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    LOCAL_OUTLIER_FACTOR_NAME,
    SupervisedDetectorConfig,
    detect_flow_feature_rows,
    detect_flow_feature_rows_anomaly,
    detect_flow_feature_rows_supervised,
    fit_anomaly_detector,
    fit_supervised_detector,
)
from beacon_detector.features import FlowFeatures, extract_features_from_flows
from beacon_detector.flows import build_flows

from .cache import FeatureCacheConfig, FEATURE_SCHEMA_VERSION, get_or_build_feature_rows
from .runner import (
    STATISTICAL_REFERENCE_SEED_OFFSET,
    SUPERVISED_TRAINING_SEEDS,
    build_default_evaluation_grid,
    build_statistical_reference_features,
    build_supervised_training_features,
)
from .supervised_ablation import SupervisedFeatureSet, feature_set_by_name

MINIMUM_EVIDENCE_EVENT_COUNTS = (3, 5, 7, 9, 12, 15, 18, 24)
MINIMUM_EVIDENCE_SEEDS = (990, 991, 992)
MINIMUM_EVIDENCE_RELIABILITY_TARGETS = (0.80, 0.90)
MINIMUM_EVIDENCE_RF_OPERATING_POINTS = (
    ("rf_full_threshold_0p6", "full", 0.6),
    ("rf_full_threshold_0p3", "full", 0.3),
)


@dataclass(frozen=True, slots=True)
class MinimumEvidenceScenario:
    scenario_family: str
    generation_scenario: GenerationScenario
    description: str
    base_config: SyntheticTrafficConfig


@dataclass(frozen=True, slots=True)
class MinimumEvidenceCase:
    scenario_family: str
    event_count: int
    generation_scenario: GenerationScenario
    config: SyntheticTrafficConfig

    @property
    def cache_name(self) -> str:
        return f"{self.scenario_family}_events_{self.event_count}"


@dataclass(frozen=True, slots=True)
class MinimumEvidenceRecord:
    detector_name: str
    operating_point: str
    scenario_family: str
    event_count: int
    seed: int
    scenario_name: str | None
    true_label: str
    predicted_label: str
    score: float


@dataclass(frozen=True, slots=True)
class MinimumEvidenceSummaryRow:
    detector_name: str
    operating_point: str
    scenario_family: str
    event_count: int
    beacon_flow_count: int
    mean_score: float | None
    median_score: float | None
    min_score: float | None
    max_score: float | None
    detection_rate: float
    false_negative_count: int
    benign_false_positive_rate: float
    benign_false_positive_count: int


@dataclass(frozen=True, slots=True)
class MinimumEvidenceThresholdRow:
    detector_name: str
    operating_point: str
    scenario_family: str
    reliability_target: float
    first_reliable_event_count: int | None


@dataclass(frozen=True, slots=True)
class MinimumEvidenceResult:
    summary_rows: tuple[MinimumEvidenceSummaryRow, ...]
    threshold_rows: tuple[MinimumEvidenceThresholdRow, ...]
    records: tuple[MinimumEvidenceRecord, ...]


def build_minimum_evidence_scenarios(
    start_time: datetime | None = None,
) -> list[MinimumEvidenceScenario]:
    start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = SyntheticTrafficConfig(
        start_time=start_time,
        seed=990,
        normal_event_count=180,
        normal_flow_count=30,
        normal_events_per_flow_min=5,
        normal_events_per_flow_max=9,
        beacon_event_count=12,
        mean_interval_seconds=60.0,
        duration_seconds=5400,
        beacon_size_bytes=150,
    )
    overlap_profiles = (
        NormalTrafficProfile.KEEPALIVE,
        NormalTrafficProfile.TELEMETRY,
        NormalTrafficProfile.API_POLLING,
        NormalTrafficProfile.BURSTY_SESSION,
        NormalTrafficProfile.SOFTWARE_UPDATE,
    )
    return [
        MinimumEvidenceScenario(
            scenario_family="fixed_periodic",
            generation_scenario=GenerationScenario.FIXED,
            description="Stable periodic beaconing with fixed interval and size.",
            base_config=replace(base, mean_interval_seconds=60.0),
        ),
        MinimumEvidenceScenario(
            scenario_family="jittered",
            generation_scenario=GenerationScenario.JITTERED,
            description="Representative timing-jittered beaconing.",
            base_config=replace(base, jitter_fraction=0.55),
        ),
        MinimumEvidenceScenario(
            scenario_family="bursty",
            generation_scenario=GenerationScenario.BURSTY,
            description="Representative burst/sleep beaconing.",
            base_config=replace(
                base,
                burst_size_min=2,
                burst_size_max=4,
                sleep_duration_seconds=180.0,
            ),
        ),
        MinimumEvidenceScenario(
            scenario_family="time_size_jittered",
            generation_scenario=GenerationScenario.TIME_SIZE_JITTERED,
            description="High timing and size jitter without extra benign overlap.",
            base_config=replace(
                base,
                jitter_fraction=0.75,
                beacon_size_jitter_fraction=0.75,
                time_size_jittered_jitter_fraction=0.75,
                time_size_jittered_size_jitter_fraction=0.75,
            ),
        ),
        MinimumEvidenceScenario(
            scenario_family="hard_time_size_jittered_overlap",
            generation_scenario=GenerationScenario.TIME_SIZE_JITTERED,
            description="Low-evidence hard time+size jitter with high benign overlap.",
            base_config=replace(
                base,
                normal_event_count=220,
                normal_flow_count=36,
                beacon_size_bytes=175,
                mean_interval_seconds=70.0,
                shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
                normal_profiles=overlap_profiles,
                time_size_jittered_mean_interval_seconds=70.0,
                time_size_jittered_jitter_fraction=0.95,
                time_size_jittered_size_jitter_fraction=0.95,
            ),
        ),
    ]


def build_minimum_evidence_cases(
    event_counts: tuple[int, ...] = MINIMUM_EVIDENCE_EVENT_COUNTS,
    start_time: datetime | None = None,
) -> list[MinimumEvidenceCase]:
    cases: list[MinimumEvidenceCase] = []
    for scenario in build_minimum_evidence_scenarios(start_time=start_time):
        for event_count in event_counts:
            config = _with_event_count(scenario.base_config, scenario.generation_scenario, event_count)
            cases.append(
                MinimumEvidenceCase(
                    scenario_family=scenario.scenario_family,
                    event_count=event_count,
                    generation_scenario=scenario.generation_scenario,
                    config=config,
                )
            )
    return cases


def run_minimum_evidence_study(
    *,
    cases: list[MinimumEvidenceCase] | None = None,
    seeds: tuple[int, ...] = MINIMUM_EVIDENCE_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
    cache_config: FeatureCacheConfig | None = None,
) -> MinimumEvidenceResult:
    cases = cases or build_minimum_evidence_cases()
    records: list[MinimumEvidenceRecord] = []
    records.extend(_run_rule_detector(cases, seeds, cache_config))
    records.extend(_run_lof_detector(cases, seeds, cache_config))
    records.extend(_run_rf_detectors(cases, seeds, training_seeds, cache_config))
    summary_rows = tuple(_summarize_records(records))
    return MinimumEvidenceResult(
        summary_rows=summary_rows,
        threshold_rows=tuple(_reliability_thresholds(summary_rows)),
        records=tuple(records),
    )


def export_minimum_evidence_tables(
    *,
    output_dir: str | Path,
    result: MinimumEvidenceResult,
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...] = MINIMUM_EVIDENCE_SEEDS,
    training_seeds: tuple[int, ...] = SUPERVISED_TRAINING_SEEDS,
) -> list[Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return [
        _write_summary(output_path, result),
        _write_detection_curves(output_path, result),
        _write_thresholds(output_path, result),
        _write_metadata(output_path, cases=cases, seeds=seeds, training_seeds=training_seeds),
    ]


def _run_rule_detector(
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[MinimumEvidenceRecord]:
    records: list[MinimumEvidenceRecord] = []
    operating_point = f"threshold={FROZEN_RULE_BASELINE_THRESHOLDS.prediction_threshold:g}"
    for case, seed in _iter_seeded_cases(cases, seeds):
        rows = _case_features(case, seed=seed, cache_config=cache_config)
        results = detect_flow_feature_rows(rows, thresholds=FROZEN_RULE_BASELINE_THRESHOLDS)
        records.extend(_records_from_results(FROZEN_RULE_BASELINE_NAME, operating_point, case, results))
    return records


def _run_lof_detector(
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[MinimumEvidenceRecord]:
    records: list[MinimumEvidenceRecord] = []
    config = AnomalyDetectorConfig()
    for seed in seeds:
        reference_features = build_statistical_reference_features(
            seed=seed + STATISTICAL_REFERENCE_SEED_OFFSET,
            cache_config=cache_config,
        )
        model = fit_anomaly_detector(
            reference_features,
            detector_type="local_outlier_factor",
            config=config,
        )
        for case in cases:
            seeded_case = replace(case, config=replace(case.config, seed=seed))
            rows = _case_features(seeded_case, seed=seed, cache_config=cache_config)
            results = detect_flow_feature_rows_anomaly(rows, model=model)
            records.extend(_records_from_results(LOCAL_OUTLIER_FACTOR_NAME, "default_lof", seeded_case, results))
    return records


def _run_rf_detectors(
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
    cache_config: FeatureCacheConfig | None,
) -> list[MinimumEvidenceRecord]:
    training_features = build_supervised_training_features(
        training_seeds=training_seeds,
        training_cases=build_default_evaluation_grid(),
        cache_config=cache_config,
    )
    records: list[MinimumEvidenceRecord] = []
    for detector_name, feature_set_name, threshold in MINIMUM_EVIDENCE_RF_OPERATING_POINTS:
        feature_set = feature_set_by_name(feature_set_name)
        config = SupervisedDetectorConfig(
            feature_names=feature_set.feature_names,
            prediction_threshold=threshold,
        )
        model = fit_supervised_detector(
            training_features,
            detector_type="random_forest",
            config=config,
        )
        operating_point = f"threshold={threshold:g};features={feature_set.name}"
        for case, seed in _iter_seeded_cases(cases, seeds):
            rows = _case_features(case, seed=seed, cache_config=cache_config)
            results = detect_flow_feature_rows_supervised(rows, model=model)
            records.extend(_records_from_results(detector_name, operating_point, case, results))
    return records


def _iter_seeded_cases(
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...],
):
    for seed in seeds:
        for case in cases:
            yield replace(case, config=replace(case.config, seed=seed)), seed


def _case_features(
    case: MinimumEvidenceCase,
    *,
    seed: int,
    cache_config: FeatureCacheConfig | None,
) -> list[FlowFeatures]:
    result = get_or_build_feature_rows(
        cache_config=cache_config,
        cache_kind="minimum_evidence_case",
        cache_name=case.cache_name,
        seed=seed,
        source_config=case.config,
        build_rows=lambda: _extract_minimum_evidence_features(case),
    )
    return result.rows


def _extract_minimum_evidence_features(case: MinimumEvidenceCase) -> list[FlowFeatures]:
    events = generate_synthetic_events(case.config, case.generation_scenario)
    return extract_features_from_flows(build_flows(events))


def _records_from_results(
    detector_name: str,
    operating_point: str,
    case: MinimumEvidenceCase,
    results,
) -> list[MinimumEvidenceRecord]:
    return [
        MinimumEvidenceRecord(
            detector_name=detector_name,
            operating_point=operating_point,
            scenario_family=case.scenario_family,
            event_count=case.event_count,
            seed=case.config.seed,
            scenario_name=result.scenario_name,
            true_label=result.true_label,
            predicted_label=result.predicted_label,
            score=result.score,
        )
        for result in results
    ]


def _summarize_records(
    records: list[MinimumEvidenceRecord],
) -> list[MinimumEvidenceSummaryRow]:
    keys = sorted(
        {
            (
                record.detector_name,
                record.operating_point,
                record.scenario_family,
                record.event_count,
            )
            for record in records
        }
    )
    rows: list[MinimumEvidenceSummaryRow] = []
    for detector_name, operating_point, scenario_family, event_count in keys:
        group = [
            record
            for record in records
            if record.detector_name == detector_name
            and record.operating_point == operating_point
            and record.scenario_family == scenario_family
            and record.event_count == event_count
        ]
        beacon_records = [record for record in group if record.true_label == "beacon"]
        benign_records = [record for record in group if record.true_label == "benign"]
        detected = [record for record in beacon_records if record.predicted_label == "beacon"]
        false_positives = [record for record in benign_records if record.predicted_label == "beacon"]
        scores = [record.score for record in beacon_records]
        rows.append(
            MinimumEvidenceSummaryRow(
                detector_name=detector_name,
                operating_point=operating_point,
                scenario_family=scenario_family,
                event_count=event_count,
                beacon_flow_count=len(beacon_records),
                mean_score=_mean(scores),
                median_score=_median(scores),
                min_score=min(scores) if scores else None,
                max_score=max(scores) if scores else None,
                detection_rate=len(detected) / len(beacon_records) if beacon_records else 0.0,
                false_negative_count=len(beacon_records) - len(detected),
                benign_false_positive_rate=(
                    len(false_positives) / len(benign_records) if benign_records else 0.0
                ),
                benign_false_positive_count=len(false_positives),
            )
        )
    return rows


def _reliability_thresholds(
    rows: tuple[MinimumEvidenceSummaryRow, ...],
) -> list[MinimumEvidenceThresholdRow]:
    keys = sorted(
        {
            (row.detector_name, row.operating_point, row.scenario_family)
            for row in rows
        }
    )
    threshold_rows: list[MinimumEvidenceThresholdRow] = []
    for detector_name, operating_point, scenario_family in keys:
        subset = sorted(
            [
                row
                for row in rows
                if row.detector_name == detector_name
                and row.operating_point == operating_point
                and row.scenario_family == scenario_family
            ],
            key=lambda row: row.event_count,
        )
        for target in MINIMUM_EVIDENCE_RELIABILITY_TARGETS:
            first = next(
                (
                    row.event_count
                    for index, row in enumerate(subset)
                    if row.detection_rate >= target
                    and all(
                        later.detection_rate >= target
                        for later in subset[index:]
                    )
                ),
                None,
            )
            threshold_rows.append(
                MinimumEvidenceThresholdRow(
                    detector_name=detector_name,
                    operating_point=operating_point,
                    scenario_family=scenario_family,
                    reliability_target=target,
                    first_reliable_event_count=first,
                )
            )
    return threshold_rows


def _with_event_count(
    config: SyntheticTrafficConfig,
    scenario: GenerationScenario,
    event_count: int,
) -> SyntheticTrafficConfig:
    if scenario is GenerationScenario.TIME_SIZE_JITTERED:
        return replace(
            config,
            beacon_event_count=event_count,
            time_size_jittered_event_count=event_count,
        )
    return replace(config, beacon_event_count=event_count)


def _write_summary(output_dir: Path, result: MinimumEvidenceResult) -> Path:
    path = output_dir / "minimum_evidence_summary.csv"
    _write_csv(path, [asdict(row) for row in result.summary_rows])
    return path


def _write_detection_curves(output_dir: Path, result: MinimumEvidenceResult) -> Path:
    path = output_dir / "minimum_evidence_detection_curves.csv"
    rows = [
        {
            "detector_name": row.detector_name,
            "operating_point": row.operating_point,
            "scenario_family": row.scenario_family,
            "event_count": row.event_count,
            "mean_score": row.mean_score,
            "median_score": row.median_score,
            "detection_rate": row.detection_rate,
            "benign_false_positive_rate": row.benign_false_positive_rate,
        }
        for row in result.summary_rows
    ]
    _write_csv(path, rows)
    return path


def _write_thresholds(output_dir: Path, result: MinimumEvidenceResult) -> Path:
    path = output_dir / "minimum_evidence_thresholds.csv"
    _write_csv(path, [asdict(row) for row in result.threshold_rows])
    return path


def _write_metadata(
    output_dir: Path,
    *,
    cases: list[MinimumEvidenceCase],
    seeds: tuple[int, ...],
    training_seeds: tuple[int, ...],
) -> Path:
    path = output_dir / "minimum_evidence_metadata.json"
    metadata = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "purpose": "Controlled minimum-evidence event-count study for beacon detection.",
        "event_counts": list(MINIMUM_EVIDENCE_EVENT_COUNTS),
        "reliability_targets": list(MINIMUM_EVIDENCE_RELIABILITY_TARGETS),
        "seed_list": list(seeds),
        "training_seed_list": list(training_seeds),
        "detectors": [
            FROZEN_RULE_BASELINE_NAME,
            LOCAL_OUTLIER_FACTOR_NAME,
            *(name for name, _, _ in MINIMUM_EVIDENCE_RF_OPERATING_POINTS),
        ],
        "scenario_families": sorted({case.scenario_family for case in cases}),
        "cases": [
            {
                "scenario_family": case.scenario_family,
                "event_count": case.event_count,
                "generation_scenario": case.generation_scenario.value,
                "jitter_fraction": case.config.jitter_fraction,
                "beacon_size_jitter_fraction": case.config.beacon_size_jitter_fraction,
                "time_size_jittered_jitter_fraction": case.config.time_size_jittered_jitter_fraction,
                "time_size_jittered_size_jitter_fraction": case.config.time_size_jittered_size_jitter_fraction,
                "shortcut_overlap_level": ShortcutOverlapLevel(
                    case.config.shortcut_overlap_level
                ).value,
            }
            for case in cases
        ],
        "outputs": [
            "minimum_evidence_summary.csv",
            "minimum_evidence_detection_curves.csv",
            "minimum_evidence_thresholds.csv",
            "minimum_evidence_metadata.json",
        ],
    }
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return path


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    return float(median(values))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
