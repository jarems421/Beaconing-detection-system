from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from beacon_detector.flows import Flow

from .models import FlowFeatures


@dataclass(frozen=True, slots=True)
class BurstSummary:
    burst_sizes: tuple[int, ...]
    sleep_durations_seconds: tuple[float, ...]
    within_burst_gaps_seconds: tuple[float, ...]
    total_burst_duration_seconds: float
    total_sleep_duration_seconds: float


def extract_features_from_flow(
    flow: Flow,
    burst_threshold_seconds: float = 10.0,
    timing_consistency_tolerance_fraction: float = 0.20,
) -> FlowFeatures:
    """Extract behavioural features from a single flow.

    Bursts are runs of at least two consecutive events where each adjacent
    inter-arrival time is less than or equal to the configured threshold.
    """

    sizes = [event.size_bytes for event in flow.events]
    interarrivals = calculate_interarrival_times(flow)
    burst_summary = detect_bursts(interarrivals, burst_threshold_seconds)
    trimmed_cv = calculate_trimmed_cv(interarrivals)
    near_median_fraction = calculate_near_median_fraction(
        interarrivals,
        tolerance_fraction=timing_consistency_tolerance_fraction,
    )
    interval_bin_summary = calculate_adaptive_bin_summary(interarrivals)
    size_bin_summary = calculate_adaptive_bin_summary(sizes)
    dominant_fraction = calculate_dominant_interval_fraction(
        interarrivals,
        tolerance_fraction=timing_consistency_tolerance_fraction,
    )

    duration = flow.duration_seconds if flow.event_count > 0 else None
    events_per_second = _safe_rate(flow.event_count, duration)

    return FlowFeatures(
        flow_key=flow.flow_key,
        label=flow.label,
        scenario_name=_scenario_name_for_features(flow),
        event_count=flow.event_count,
        total_bytes=flow.total_bytes,
        flow_duration_seconds=duration,
        mean_interarrival_seconds=_mean(interarrivals),
        median_interarrival_seconds=_median(interarrivals),
        std_interarrival_seconds=_std(interarrivals),
        min_interarrival_seconds=min(interarrivals) if interarrivals else None,
        max_interarrival_seconds=max(interarrivals) if interarrivals else None,
        interarrival_iqr_seconds=calculate_iqr(interarrivals),
        interarrival_mad_seconds=calculate_mad(interarrivals),
        inter_arrival_cv=_coefficient_of_variation(interarrivals),
        trimmed_interarrival_cv=trimmed_cv,
        near_median_interarrival_fraction=near_median_fraction,
        interarrival_within_10pct_median_fraction=calculate_near_median_fraction(
            interarrivals,
            tolerance_fraction=0.10,
        ),
        interarrival_within_20pct_median_fraction=calculate_near_median_fraction(
            interarrivals,
            tolerance_fraction=0.20,
        ),
        interarrival_within_30pct_median_fraction=calculate_near_median_fraction(
            interarrivals,
            tolerance_fraction=0.30,
        ),
        dominant_interval_fraction=dominant_fraction,
        dominant_interval_bin_fraction=interval_bin_summary.dominant_bin_fraction,
        interval_bin_count=interval_bin_summary.bin_count,
        adjacent_gap_similarity_fraction=calculate_adjacent_similarity_fraction(
            interarrivals,
            tolerance_fraction=0.30,
        ),
        longest_similar_gap_run=calculate_longest_similar_run(
            interarrivals,
            tolerance_fraction=0.30,
        ),
        gap_range_median_ratio=calculate_range_median_ratio(interarrivals),
        interarrival_median_absolute_percentage_deviation=calculate_median_absolute_percentage_deviation(
            interarrivals
        ),
        periodicity_score=_periodicity_score(
            near_median_fraction,
            trimmed_cv,
        ),
        events_per_second=events_per_second,
        events_per_minute=events_per_second * 60.0 if events_per_second is not None else None,
        burst_count=len(burst_summary.burst_sizes),
        avg_burst_size=_mean(list(burst_summary.burst_sizes)),
        max_burst_size=max(burst_summary.burst_sizes) if burst_summary.burst_sizes else None,
        burst_size_variance=_variance(list(burst_summary.burst_sizes)),
        avg_sleep_duration_seconds=_mean(list(burst_summary.sleep_durations_seconds)),
        sleep_duration_variance=_variance(list(burst_summary.sleep_durations_seconds)),
        burst_size_cv=_coefficient_of_variation(list(burst_summary.burst_sizes)),
        sleep_duration_cv=_coefficient_of_variation(
            list(burst_summary.sleep_durations_seconds)
        ),
        within_burst_gap_consistency=calculate_near_median_fraction(
            list(burst_summary.within_burst_gaps_seconds),
            tolerance_fraction=0.30,
        ),
        burst_to_idle_ratio=_burst_to_idle_ratio(burst_summary),
        mean_size_bytes=_mean(sizes),
        median_size_bytes=_median(sizes),
        std_size_bytes=_std(sizes),
        size_cv=_coefficient_of_variation(sizes),
        dominant_size_bin_fraction=size_bin_summary.dominant_bin_fraction,
        size_bin_count=size_bin_summary.bin_count,
        normalized_size_range=calculate_range_median_ratio(sizes),
        near_median_size_fraction=calculate_near_median_fraction(
            sizes,
            tolerance_fraction=0.20,
        ),
    )


def extract_features_from_flows(
    flows: list[Flow],
    burst_threshold_seconds: float = 10.0,
    timing_consistency_tolerance_fraction: float = 0.20,
) -> list[FlowFeatures]:
    return [
        extract_features_from_flow(
            flow,
            burst_threshold_seconds=burst_threshold_seconds,
            timing_consistency_tolerance_fraction=timing_consistency_tolerance_fraction,
        )
        for flow in flows
    ]


def calculate_interarrival_times(flow: Flow) -> list[float]:
    timestamps = sorted(event.timestamp for event in flow.events)
    return [
        (timestamps[index] - timestamps[index - 1]).total_seconds()
        for index in range(1, len(timestamps))
    ]


def calculate_iqr(values: list[float] | list[int]) -> float | None:
    if len(values) < 2:
        return None

    ordered = sorted(float(value) for value in values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2 == 0:
        lower_half = ordered[:midpoint]
        upper_half = ordered[midpoint:]
    else:
        lower_half = ordered[:midpoint]
        upper_half = ordered[midpoint + 1 :]

    if not lower_half or not upper_half:
        return 0.0
    return float(median(upper_half) - median(lower_half))


def calculate_mad(values: list[float] | list[int]) -> float | None:
    if len(values) < 2:
        return None

    center = float(median(values))
    deviations = [abs(float(value) - center) for value in values]
    return float(median(deviations))


def calculate_trimmed_cv(
    values: list[float] | list[int],
    trim_fraction: float = 0.10,
) -> float | None:
    if not 0 <= trim_fraction < 0.5:
        raise ValueError("trim_fraction must be in the range [0, 0.5).")
    if len(values) < 2:
        return None

    ordered = sorted(float(value) for value in values)
    trim_count = int(len(ordered) * trim_fraction)
    if trim_count > 0 and len(ordered) - (2 * trim_count) >= 2:
        ordered = ordered[trim_count:-trim_count]
    return _coefficient_of_variation(ordered)


def calculate_near_median_fraction(
    values: list[float] | list[int],
    tolerance_fraction: float = 0.20,
) -> float | None:
    if tolerance_fraction < 0:
        raise ValueError("tolerance_fraction must be non-negative.")
    if not values:
        return None

    center = float(median(values))
    tolerance = abs(center) * tolerance_fraction
    matches = sum(1 for value in values if abs(float(value) - center) <= tolerance)
    return matches / len(values)


def calculate_dominant_interval_fraction(
    values: list[float] | list[int],
    tolerance_fraction: float = 0.20,
) -> float | None:
    if tolerance_fraction < 0:
        raise ValueError("tolerance_fraction must be non-negative.")
    if not values:
        return None

    float_values = [float(value) for value in values]
    best_count = 0
    for candidate in float_values:
        tolerance = abs(candidate) * tolerance_fraction
        count = sum(
            1 for value in float_values if abs(value - candidate) <= tolerance
        )
        best_count = max(best_count, count)
    return best_count / len(float_values)


@dataclass(frozen=True, slots=True)
class AdaptiveBinSummary:
    dominant_bin_fraction: float | None
    bin_count: int | None


def calculate_adaptive_bin_summary(
    values: list[float] | list[int],
    relative_bin_width: float = 0.20,
    minimum_bin_width: float = 1.0,
) -> AdaptiveBinSummary:
    if relative_bin_width <= 0:
        raise ValueError("relative_bin_width must be positive.")
    if minimum_bin_width <= 0:
        raise ValueError("minimum_bin_width must be positive.")
    if not values:
        return AdaptiveBinSummary(None, None)

    center = abs(float(median(values)))
    bin_width = max(minimum_bin_width, center * relative_bin_width)
    counts: dict[int, int] = {}
    for value in values:
        bucket = int(round(float(value) / bin_width))
        counts[bucket] = counts.get(bucket, 0) + 1

    return AdaptiveBinSummary(
        dominant_bin_fraction=max(counts.values()) / len(values),
        bin_count=len(counts),
    )


def calculate_adjacent_similarity_fraction(
    values: list[float] | list[int],
    tolerance_fraction: float = 0.30,
) -> float | None:
    if tolerance_fraction < 0:
        raise ValueError("tolerance_fraction must be non-negative.")
    if len(values) < 2:
        return None

    pairs = list(zip(values, values[1:]))
    matches = sum(
        1
        for left, right in pairs
        if _relative_difference(float(left), float(right)) <= tolerance_fraction
    )
    return matches / len(pairs)


def calculate_longest_similar_run(
    values: list[float] | list[int],
    tolerance_fraction: float = 0.30,
) -> int | None:
    if tolerance_fraction < 0:
        raise ValueError("tolerance_fraction must be non-negative.")
    if not values:
        return None
    if len(values) == 1:
        return 1

    longest_run = 1
    current_run = 1
    for left, right in zip(values, values[1:]):
        if _relative_difference(float(left), float(right)) <= tolerance_fraction:
            current_run += 1
        else:
            longest_run = max(longest_run, current_run)
            current_run = 1
    return max(longest_run, current_run)


def calculate_range_median_ratio(values: list[float] | list[int]) -> float | None:
    if not values:
        return None
    center = float(median(values))
    if center == 0:
        return None
    return (max(values) - min(values)) / abs(center)


def calculate_median_absolute_percentage_deviation(
    values: list[float] | list[int],
) -> float | None:
    if not values:
        return None
    center = float(median(values))
    if center == 0:
        return None
    percentage_deviations = [
        abs(float(value) - center) / abs(center)
        for value in values
    ]
    return float(median(percentage_deviations))


def detect_bursts(
    interarrival_times_seconds: list[float],
    burst_threshold_seconds: float,
) -> BurstSummary:
    if burst_threshold_seconds < 0:
        raise ValueError("burst_threshold_seconds must be non-negative.")
    if not interarrival_times_seconds:
        return BurstSummary((), (), (), 0.0, 0.0)

    burst_sizes: list[int] = []
    sleep_durations: list[float] = []
    within_burst_gaps: list[float] = []
    total_burst_duration = 0.0
    total_sleep_duration = 0.0
    current_burst_size = 1

    for gap in interarrival_times_seconds:
        if gap <= burst_threshold_seconds:
            current_burst_size += 1
            within_burst_gaps.append(gap)
            total_burst_duration += gap
        else:
            if current_burst_size >= 2:
                burst_sizes.append(current_burst_size)
            sleep_durations.append(gap)
            total_sleep_duration += gap
            current_burst_size = 1

    if current_burst_size >= 2:
        burst_sizes.append(current_burst_size)

    return BurstSummary(
        burst_sizes=tuple(burst_sizes),
        sleep_durations_seconds=tuple(sleep_durations),
        within_burst_gaps_seconds=tuple(within_burst_gaps),
        total_burst_duration_seconds=total_burst_duration,
        total_sleep_duration_seconds=total_sleep_duration,
    )


def _scenario_name_for_features(flow: Flow) -> str | None:
    if not flow.scenario_names:
        return None
    if len(flow.scenario_names) == 1:
        return flow.scenario_names[0]
    return ",".join(flow.scenario_names)


def _mean(values: list[float] | list[int]) -> float | None:
    if not values:
        return None
    return float(sum(values) / len(values))


def _median(values: list[float] | list[int]) -> float | None:
    if not values:
        return None
    return float(median(values))


def _variance(values: list[float] | list[int]) -> float | None:
    if not values:
        return None
    mean_value = sum(values) / len(values)
    return float(sum((value - mean_value) ** 2 for value in values) / len(values))


def _std(values: list[float] | list[int]) -> float | None:
    variance = _variance(values)
    if variance is None:
        return None
    return variance**0.5


def _coefficient_of_variation(values: list[float] | list[int]) -> float | None:
    mean_value = _mean(values)
    std_value = _std(values)
    if mean_value is None or std_value is None or mean_value == 0:
        return None
    return std_value / mean_value


def _relative_difference(left: float, right: float) -> float:
    denominator = max(abs(left), abs(right), 1e-12)
    return abs(left - right) / denominator


def _periodicity_score(
    near_median_fraction: float | None,
    trimmed_cv: float | None,
) -> float | None:
    if near_median_fraction is None or trimmed_cv is None:
        return None
    return near_median_fraction / (1.0 + trimmed_cv)


def _safe_rate(count: int, duration_seconds: float | None) -> float | None:
    if duration_seconds is None or duration_seconds <= 0:
        return None
    return count / duration_seconds


def _burst_to_idle_ratio(summary: BurstSummary) -> float | None:
    if summary.total_sleep_duration_seconds <= 0:
        return None
    return summary.total_burst_duration_seconds / summary.total_sleep_duration_seconds
