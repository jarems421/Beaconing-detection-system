from __future__ import annotations

from dataclasses import dataclass

from beacon_detector.data.types import TrafficLabel
from beacon_detector.flows.models import FlowKey


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    """Feature record derived from a single flow."""

    flow_key: FlowKey
    label: TrafficLabel
    scenario_name: str | None = None

    event_count: int = 0
    total_bytes: int = 0
    flow_duration_seconds: float | None = None

    mean_interarrival_seconds: float | None = None
    median_interarrival_seconds: float | None = None
    std_interarrival_seconds: float | None = None
    min_interarrival_seconds: float | None = None
    max_interarrival_seconds: float | None = None
    interarrival_iqr_seconds: float | None = None
    interarrival_mad_seconds: float | None = None
    inter_arrival_cv: float | None = None
    trimmed_interarrival_cv: float | None = None
    near_median_interarrival_fraction: float | None = None
    interarrival_within_10pct_median_fraction: float | None = None
    interarrival_within_20pct_median_fraction: float | None = None
    interarrival_within_30pct_median_fraction: float | None = None
    dominant_interval_fraction: float | None = None
    dominant_interval_bin_fraction: float | None = None
    interval_bin_count: int | None = None
    adjacent_gap_similarity_fraction: float | None = None
    longest_similar_gap_run: int | None = None
    gap_range_median_ratio: float | None = None
    interarrival_median_absolute_percentage_deviation: float | None = None
    periodicity_score: float | None = None

    events_per_second: float | None = None
    events_per_minute: float | None = None

    burst_count: int | None = None
    avg_burst_size: float | None = None
    max_burst_size: int | None = None
    burst_size_variance: float | None = None
    avg_sleep_duration_seconds: float | None = None
    sleep_duration_variance: float | None = None
    burst_size_cv: float | None = None
    sleep_duration_cv: float | None = None
    within_burst_gap_consistency: float | None = None
    burst_to_idle_ratio: float | None = None

    mean_size_bytes: float | None = None
    median_size_bytes: float | None = None
    std_size_bytes: float | None = None
    size_cv: float | None = None
    dominant_size_bin_fraction: float | None = None
    size_bin_count: int | None = None
    normalized_size_range: float | None = None
    near_median_size_fraction: float | None = None
