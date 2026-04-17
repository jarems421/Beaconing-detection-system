from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
import random

from .loader import save_events_to_csv
from .types import ProtocolType, TrafficEvent


class GenerationScenario(str, Enum):
    NORMAL = "normal"
    FIXED = "fixed_periodic"
    JITTERED = "jittered"
    BURSTY = "bursty"
    TIME_SIZE_JITTERED = "time_size_jittered"


class NormalTrafficProfile(str, Enum):
    SOFTWARE_UPDATE = "normal_software_update"
    TELEMETRY = "normal_telemetry"
    CLOUD_SYNC = "normal_cloud_sync"
    API_POLLING = "normal_api_polling"
    BURSTY_SESSION = "normal_bursty_session"
    KEEPALIVE = "normal_keepalive"


class ShortcutOverlapLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class SyntheticTrafficConfig:
    start_time: datetime | None = None
    seed: int = 7

    normal_event_count: int = 160
    normal_flow_count: int = 6
    normal_events_per_flow_min: int = 3
    normal_events_per_flow_max: int = 10
    beacon_event_count: int = 40
    duration_seconds: int = 3600

    normal_start_offset_seconds: float = 17.0
    fixed_start_offset_seconds: float = 0.0
    jittered_start_offset_seconds: float = 43.0
    bursty_start_offset_seconds: float = 91.0
    time_size_jittered_start_offset_seconds: float = 137.0

    mean_interval_seconds: float = 60.0
    jitter_fraction: float = 0.35
    sleep_duration_seconds: float = 300.0
    burst_size_min: int = 2
    burst_size_max: int = 5

    beacon_size_bytes: int = 120
    beacon_size_jitter_fraction: float = 0.25
    normal_size_min_bytes: int = 60
    normal_size_max_bytes: int = 1500
    normal_min_gap_seconds: float = 1.0
    normal_max_gap_seconds: float = 240.0
    normal_profiles: tuple[NormalTrafficProfile, ...] = (
        NormalTrafficProfile.SOFTWARE_UPDATE,
        NormalTrafficProfile.TELEMETRY,
        NormalTrafficProfile.CLOUD_SYNC,
        NormalTrafficProfile.API_POLLING,
        NormalTrafficProfile.BURSTY_SESSION,
        NormalTrafficProfile.KEEPALIVE,
    )
    shortcut_overlap_level: ShortcutOverlapLevel = ShortcutOverlapLevel.LOW

    time_size_jittered_event_count: int | None = None
    time_size_jittered_mean_interval_seconds: float | None = None
    time_size_jittered_jitter_fraction: float | None = None
    time_size_jittered_size_jitter_fraction: float | None = None

    normal_src_ips: tuple[str, ...] = (
        "10.0.0.10",
        "10.0.0.25",
        "10.0.1.8",
        "10.0.2.14",
    )
    normal_dst_ips: tuple[str, ...] = (
        "198.51.100.20",
        "198.51.100.44",
        "203.0.113.8",
        "203.0.113.77",
    )
    normal_dst_ports: tuple[int, ...] = (53, 80, 123, 443, 8080)
    normal_protocols: tuple[ProtocolType, ...] = ("tcp", "udp")

    beacon_src_ip: str = "10.10.10.5"
    beacon_dst_ip: str = "203.0.113.10"
    beacon_dst_port: int = 443
    beacon_protocol: ProtocolType = "tcp"

    jittered_beacon_src_ip: str = "10.10.10.6"
    jittered_beacon_dst_ip: str = "203.0.113.11"
    jittered_beacon_dst_port: int = 443
    jittered_beacon_protocol: ProtocolType = "tcp"

    bursty_beacon_src_ip: str = "10.10.10.7"
    bursty_beacon_dst_ip: str = "203.0.113.12"
    bursty_beacon_dst_port: int = 8443
    bursty_beacon_protocol: ProtocolType = "tcp"

    time_size_jittered_beacon_src_ip: str = "10.10.10.8"
    time_size_jittered_beacon_dst_ip: str = "203.0.113.13"
    time_size_jittered_beacon_dst_port: int = 9443
    time_size_jittered_beacon_protocol: ProtocolType = "tcp"


def generate_normal_traffic(
    config: SyntheticTrafficConfig,
    rng: random.Random | None = None,
) -> list[TrafficEvent]:
    rng = rng or random.Random(config.seed)
    start_time = _scenario_start_time(config, GenerationScenario.NORMAL)

    events: list[TrafficEvent] = []
    used_flow_keys: set[tuple[str, str, int, ProtocolType]] = set()
    flow_lengths = _allocate_normal_flow_lengths(config, rng)
    profiles = _allocate_normal_profiles(config, len(flow_lengths), rng)
    for flow_length, profile in zip(flow_lengths, profiles):
        src_ip, dst_ip, dst_port, protocol = _sample_normal_flow_identity(
            config,
            rng,
            used_flow_keys,
        )
        elapsed = rng.uniform(0.0, max(float(config.duration_seconds) * 0.75, 1.0))
        for event_index in range(flow_length):
            events.append(
                TrafficEvent(
                    timestamp=start_time + timedelta(seconds=elapsed),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    size_bytes=_sample_normal_size(config, rng, profile),
                    label="benign",
                    scenario_name=profile.value,
                )
            )
            elapsed += _sample_normal_gap(config, rng, profile, event_index)
    return sorted(events, key=lambda event: event.timestamp)


def generate_fixed_beaconing(
    config: SyntheticTrafficConfig,
    rng: random.Random | None = None,
) -> list[TrafficEvent]:
    rng = rng or random.Random(config.seed)
    return _generate_beacon_sequence(
        config=config,
        rng=rng,
        scenario_name=GenerationScenario.FIXED.value,
        interval_sampler=lambda: config.mean_interval_seconds,
        size_sampler=lambda: config.beacon_size_bytes,
    )


def generate_jittered_beaconing(
    config: SyntheticTrafficConfig,
    rng: random.Random | None = None,
) -> list[TrafficEvent]:
    rng = rng or random.Random(config.seed)
    return _generate_beacon_sequence(
        config=config,
        rng=rng,
        scenario_name=GenerationScenario.JITTERED.value,
        interval_sampler=lambda: _jittered_value(
            rng,
            config.mean_interval_seconds,
            config.jitter_fraction,
            minimum=1.0,
        ),
        size_sampler=lambda: config.beacon_size_bytes,
    )


def generate_bursty_beaconing(
    config: SyntheticTrafficConfig,
    rng: random.Random | None = None,
) -> list[TrafficEvent]:
    rng = rng or random.Random(config.seed)
    start_time = _scenario_start_time(config, GenerationScenario.BURSTY)

    events: list[TrafficEvent] = []
    elapsed = 0.0
    while len(events) < config.beacon_event_count:
        burst_size = rng.randint(config.burst_size_min, config.burst_size_max)
        for index in range(burst_size):
            if len(events) >= config.beacon_event_count:
                break
            events.append(
                _beacon_event(
                    config=config,
                    timestamp=start_time + timedelta(seconds=elapsed + index * rng.uniform(0.2, 2.0)),
                    size_bytes=config.beacon_size_bytes,
                    scenario_name=GenerationScenario.BURSTY.value,
                )
            )
        elapsed += config.sleep_duration_seconds
    return sorted(events, key=lambda event: event.timestamp)


def generate_time_size_jittered_beaconing(
    config: SyntheticTrafficConfig,
    rng: random.Random | None = None,
) -> list[TrafficEvent]:
    rng = rng or random.Random(config.seed)
    mean_interval_seconds = (
        config.time_size_jittered_mean_interval_seconds
        if config.time_size_jittered_mean_interval_seconds is not None
        else config.mean_interval_seconds
    )
    jitter_fraction = (
        config.time_size_jittered_jitter_fraction
        if config.time_size_jittered_jitter_fraction is not None
        else config.jitter_fraction
    )
    size_jitter_fraction = (
        config.time_size_jittered_size_jitter_fraction
        if config.time_size_jittered_size_jitter_fraction is not None
        else config.beacon_size_jitter_fraction
    )
    return _generate_beacon_sequence(
        config=config,
        rng=rng,
        scenario_name=GenerationScenario.TIME_SIZE_JITTERED.value,
        interval_sampler=lambda: _jittered_value(
            rng,
            mean_interval_seconds,
            jitter_fraction,
            minimum=1.0,
        ),
        size_sampler=lambda: int(
            round(
                _jittered_value(
                    rng,
                    float(config.beacon_size_bytes),
                    size_jitter_fraction,
                    minimum=40.0,
                )
            )
        ),
        event_count=config.time_size_jittered_event_count,
    )


def generate_combined_synthetic_dataset(
    config: SyntheticTrafficConfig,
    include_time_size_jitter: bool = True,
) -> list[TrafficEvent]:
    rng = random.Random(config.seed)
    events: list[TrafficEvent] = []
    events.extend(generate_normal_traffic(config, rng))
    events.extend(generate_fixed_beaconing(config, rng))
    events.extend(generate_jittered_beaconing(config, rng))
    events.extend(generate_bursty_beaconing(config, rng))
    if include_time_size_jitter:
        events.extend(generate_time_size_jittered_beaconing(config, rng))
    return sorted(events, key=lambda event: event.timestamp)


def generate_synthetic_events(
    config: SyntheticTrafficConfig,
    scenario: GenerationScenario,
) -> list[TrafficEvent]:
    if scenario is GenerationScenario.NORMAL:
        return generate_normal_traffic(config)

    rng = random.Random(config.seed)
    events = generate_normal_traffic(config, rng)
    if scenario is GenerationScenario.FIXED:
        events.extend(generate_fixed_beaconing(config, rng))
    elif scenario is GenerationScenario.JITTERED:
        events.extend(generate_jittered_beaconing(config, rng))
    elif scenario is GenerationScenario.BURSTY:
        events.extend(generate_bursty_beaconing(config, rng))
    elif scenario is GenerationScenario.TIME_SIZE_JITTERED:
        events.extend(generate_time_size_jittered_beaconing(config, rng))
    else:
        raise ValueError(f"Unsupported generation scenario: {scenario}")
    return sorted(events, key=lambda event: event.timestamp)


def save_sample_synthetic_dataset(
    output_path: str | Path = "data/synthetic/sample_events.csv",
    config: SyntheticTrafficConfig | None = None,
) -> Path:
    config = config or SyntheticTrafficConfig()
    events = generate_combined_synthetic_dataset(config)
    return save_events_to_csv(events, output_path)


def _generate_beacon_sequence(
    *,
    config: SyntheticTrafficConfig,
    rng: random.Random,
    scenario_name: str,
    interval_sampler,
    size_sampler,
    event_count: int | None = None,
) -> list[TrafficEvent]:
    start_time = _scenario_start_time(config, GenerationScenario(scenario_name))
    events: list[TrafficEvent] = []
    elapsed = 0.0
    count = max(0, event_count if event_count is not None else config.beacon_event_count)
    for _ in range(count):
        events.append(
            _beacon_event(
                config=config,
                timestamp=start_time + timedelta(seconds=elapsed),
                size_bytes=size_sampler(),
                scenario_name=scenario_name,
            )
        )
        elapsed += interval_sampler()
    return events


def _beacon_event(
    *,
    config: SyntheticTrafficConfig,
    timestamp: datetime,
    size_bytes: int,
    scenario_name: str,
) -> TrafficEvent:
    src_ip, dst_ip, dst_port, protocol = _scenario_beacon_identity(config, scenario_name)
    return TrafficEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        size_bytes=size_bytes,
        label="beacon",
        scenario_name=scenario_name,
    )


def _scenario_beacon_identity(
    config: SyntheticTrafficConfig,
    scenario_name: str,
) -> tuple[str, str, int, ProtocolType]:
    scenario = GenerationScenario(scenario_name)
    if scenario is GenerationScenario.FIXED:
        return (
            config.beacon_src_ip,
            config.beacon_dst_ip,
            config.beacon_dst_port,
            config.beacon_protocol,
        )
    if scenario is GenerationScenario.JITTERED:
        return (
            config.jittered_beacon_src_ip,
            config.jittered_beacon_dst_ip,
            config.jittered_beacon_dst_port,
            config.jittered_beacon_protocol,
        )
    if scenario is GenerationScenario.BURSTY:
        return (
            config.bursty_beacon_src_ip,
            config.bursty_beacon_dst_ip,
            config.bursty_beacon_dst_port,
            config.bursty_beacon_protocol,
        )
    if scenario is GenerationScenario.TIME_SIZE_JITTERED:
        return (
            config.time_size_jittered_beacon_src_ip,
            config.time_size_jittered_beacon_dst_ip,
            config.time_size_jittered_beacon_dst_port,
            config.time_size_jittered_beacon_protocol,
        )
    raise ValueError(f"Scenario does not define a beacon identity: {scenario_name}")


def _allocate_normal_flow_lengths(
    config: SyntheticTrafficConfig,
    rng: random.Random,
) -> list[int]:
    if config.normal_event_count <= 0:
        return []

    min_events = max(1, config.normal_events_per_flow_min)
    max_events = max(min_events, config.normal_events_per_flow_max)
    min_flow_count_needed = (config.normal_event_count + max_events - 1) // max_events
    max_flow_count_allowed = max(1, config.normal_event_count // min_events)
    requested_flow_count = max(1, config.normal_flow_count)
    flow_count = min(
        max(requested_flow_count, min_flow_count_needed),
        max_flow_count_allowed,
    )
    if config.normal_event_count < min_events:
        return [config.normal_event_count]

    lengths = [min_events for _ in range(flow_count)]
    remaining = config.normal_event_count - sum(lengths)
    while remaining > 0:
        candidates = [index for index, length in enumerate(lengths) if length < max_events]
        if not candidates:
            lengths.append(1)
            remaining -= 1
            continue
        index = rng.choice(candidates)
        lengths[index] += 1
        remaining -= 1

    rng.shuffle(lengths)
    return lengths


def _allocate_normal_profiles(
    config: SyntheticTrafficConfig,
    flow_count: int,
    rng: random.Random,
) -> list[NormalTrafficProfile]:
    if flow_count <= 0:
        return []
    if not config.normal_profiles:
        raise ValueError("normal_profiles must contain at least one profile.")

    profiles: list[NormalTrafficProfile] = []
    while len(profiles) < flow_count:
        profiles.extend(config.normal_profiles)
    profiles = profiles[:flow_count]
    rng.shuffle(profiles)
    return profiles


def _sample_normal_flow_identity(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    used_flow_keys: set[tuple[str, str, int, ProtocolType]],
) -> tuple[str, str, int, ProtocolType]:
    for _ in range(100):
        candidate = (
            rng.choice(config.normal_src_ips),
            rng.choice(config.normal_dst_ips),
            rng.choice(config.normal_dst_ports),
            rng.choice(config.normal_protocols),
        )
        if candidate not in used_flow_keys:
            used_flow_keys.add(candidate)
            return candidate

    candidate = (
        rng.choice(config.normal_src_ips),
        rng.choice(config.normal_dst_ips),
        rng.choice(config.normal_dst_ports),
        rng.choice(config.normal_protocols),
    )
    used_flow_keys.add(candidate)
    return candidate


def _sample_normal_gap(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    profile: NormalTrafficProfile,
    event_index: int,
) -> float:
    overlap_gap = _sample_overlap_normal_gap(config, rng, profile, event_index)
    if overlap_gap is not None:
        gap = overlap_gap
    elif profile is NormalTrafficProfile.SOFTWARE_UPDATE:
        gap = _jittered_value(rng, 210.0, 0.30, minimum=45.0)
    elif profile is NormalTrafficProfile.TELEMETRY:
        gap = _jittered_value(rng, 75.0, 0.45, minimum=10.0)
    elif profile is NormalTrafficProfile.CLOUD_SYNC:
        gap = rng.uniform(20.0, 180.0)
    elif profile is NormalTrafficProfile.API_POLLING:
        gap = _jittered_value(rng, 45.0, 0.55, minimum=5.0)
    elif profile is NormalTrafficProfile.BURSTY_SESSION:
        gap = rng.uniform(45.0, 180.0) if (event_index + 1) % 3 == 0 else rng.uniform(0.5, 4.0)
    else:
        gap = _jittered_value(rng, 120.0, 0.20, minimum=20.0)
    return min(max(gap, config.normal_min_gap_seconds), config.normal_max_gap_seconds)


def _sample_normal_size(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    profile: NormalTrafficProfile,
) -> int:
    overlap_size = _sample_overlap_normal_size(config, rng, profile)
    if overlap_size is not None:
        return overlap_size

    if profile is NormalTrafficProfile.SOFTWARE_UPDATE:
        return _bounded_jittered_int(config, rng, base=420, jitter_fraction=0.20)
    elif profile is NormalTrafficProfile.TELEMETRY:
        return _bounded_jittered_int(config, rng, base=180, jitter_fraction=0.25)
    elif profile is NormalTrafficProfile.CLOUD_SYNC:
        lower, upper = 150, config.normal_size_max_bytes
    elif profile is NormalTrafficProfile.API_POLLING:
        return _bounded_jittered_int(config, rng, base=260, jitter_fraction=0.40)
    elif profile is NormalTrafficProfile.BURSTY_SESSION:
        lower, upper = 250, config.normal_size_max_bytes
    else:
        return _bounded_jittered_int(config, rng, base=96, jitter_fraction=0.12)
    configured_min = min(config.normal_size_min_bytes, config.normal_size_max_bytes)
    configured_max = max(config.normal_size_min_bytes, config.normal_size_max_bytes)
    effective_lower = max(configured_min, min(lower, configured_max))
    effective_upper = max(effective_lower, min(configured_max, upper))
    return rng.randint(effective_lower, effective_upper)


def _sample_overlap_normal_gap(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    profile: NormalTrafficProfile,
    event_index: int,
) -> float | None:
    level = _shortcut_overlap_level(config)
    if level is ShortcutOverlapLevel.LOW:
        return None

    mean = config.mean_interval_seconds
    if level is ShortcutOverlapLevel.MEDIUM:
        if profile is NormalTrafficProfile.SOFTWARE_UPDATE:
            return _jittered_value(rng, mean * 2.2, 0.45, minimum=30.0)
        if profile is NormalTrafficProfile.TELEMETRY:
            return _jittered_value(rng, mean * 1.2, 0.50, minimum=8.0)
        if profile is NormalTrafficProfile.API_POLLING:
            return _jittered_value(rng, mean * 0.8, 0.65, minimum=4.0)
        if profile is NormalTrafficProfile.KEEPALIVE:
            return _jittered_value(rng, mean * 1.6, 0.35, minimum=15.0)
        if profile is NormalTrafficProfile.BURSTY_SESSION:
            return rng.uniform(mean * 0.7, mean * 2.4) if (event_index + 1) % 3 == 0 else rng.uniform(0.5, 5.0)
        return rng.uniform(mean * 0.4, mean * 2.8)

    if profile is NormalTrafficProfile.SOFTWARE_UPDATE:
        return _jittered_value(rng, mean * 1.4, 0.70, minimum=12.0)
    if profile is NormalTrafficProfile.TELEMETRY:
        return _jittered_value(rng, mean, 0.65, minimum=5.0)
    if profile is NormalTrafficProfile.API_POLLING:
        return _jittered_value(rng, mean * 0.9, 0.80, minimum=3.0)
    if profile is NormalTrafficProfile.KEEPALIVE:
        return _jittered_value(rng, mean * 1.1, 0.45, minimum=10.0)
    if profile is NormalTrafficProfile.BURSTY_SESSION:
        return rng.uniform(mean * 0.5, mean * 1.8) if (event_index + 1) % 3 == 0 else rng.uniform(0.4, 4.5)
    return rng.uniform(mean * 0.35, mean * 2.2)


def _sample_overlap_normal_size(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    profile: NormalTrafficProfile,
) -> int | None:
    level = _shortcut_overlap_level(config)
    if level is ShortcutOverlapLevel.LOW:
        return None

    beacon_size = max(1, config.beacon_size_bytes)
    if level is ShortcutOverlapLevel.MEDIUM:
        if profile is NormalTrafficProfile.SOFTWARE_UPDATE:
            return _bounded_jittered_int(config, rng, base=int(beacon_size * 2.0), jitter_fraction=0.35)
        if profile is NormalTrafficProfile.TELEMETRY:
            return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.3), jitter_fraction=0.35)
        if profile is NormalTrafficProfile.API_POLLING:
            return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.7), jitter_fraction=0.45)
        if profile is NormalTrafficProfile.KEEPALIVE:
            return _bounded_jittered_int(config, rng, base=int(beacon_size * 0.9), jitter_fraction=0.20)
        if profile is NormalTrafficProfile.BURSTY_SESSION:
            return _bounded_jittered_int(config, rng, base=int(beacon_size * 2.4), jitter_fraction=0.70)
        return _bounded_jittered_int(config, rng, base=int(beacon_size * 2.1), jitter_fraction=0.75)

    if profile is NormalTrafficProfile.SOFTWARE_UPDATE:
        return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.5), jitter_fraction=0.60)
    if profile is NormalTrafficProfile.TELEMETRY:
        return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.1), jitter_fraction=0.55)
    if profile is NormalTrafficProfile.API_POLLING:
        return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.3), jitter_fraction=0.65)
    if profile is NormalTrafficProfile.KEEPALIVE:
        return _bounded_jittered_int(config, rng, base=int(beacon_size), jitter_fraction=0.30)
    if profile is NormalTrafficProfile.BURSTY_SESSION:
        return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.6), jitter_fraction=0.85)
    return _bounded_jittered_int(config, rng, base=int(beacon_size * 1.4), jitter_fraction=0.90)


def _shortcut_overlap_level(config: SyntheticTrafficConfig) -> ShortcutOverlapLevel:
    return ShortcutOverlapLevel(config.shortcut_overlap_level)


def _bounded_jittered_int(
    config: SyntheticTrafficConfig,
    rng: random.Random,
    base: int,
    jitter_fraction: float,
) -> int:
    configured_min = min(config.normal_size_min_bytes, config.normal_size_max_bytes)
    configured_max = max(config.normal_size_min_bytes, config.normal_size_max_bytes)
    sampled = int(round(_jittered_value(rng, float(base), jitter_fraction, minimum=1.0)))
    return min(max(sampled, configured_min), configured_max)


def _jittered_value(
    rng: random.Random,
    base: float,
    jitter_fraction: float,
    minimum: float,
) -> float:
    scale = rng.uniform(1.0 - jitter_fraction, 1.0 + jitter_fraction)
    return max(minimum, base * scale)


def _start_time(config: SyntheticTrafficConfig) -> datetime:
    return config.start_time or datetime.now(timezone.utc)


def _scenario_start_time(
    config: SyntheticTrafficConfig,
    scenario: GenerationScenario,
) -> datetime:
    return _start_time(config) + timedelta(seconds=_scenario_offset_seconds(config, scenario))


def _scenario_offset_seconds(
    config: SyntheticTrafficConfig,
    scenario: GenerationScenario,
) -> float:
    if scenario is GenerationScenario.NORMAL:
        return config.normal_start_offset_seconds
    if scenario is GenerationScenario.FIXED:
        return config.fixed_start_offset_seconds
    if scenario is GenerationScenario.JITTERED:
        return config.jittered_start_offset_seconds
    if scenario is GenerationScenario.BURSTY:
        return config.bursty_start_offset_seconds
    if scenario is GenerationScenario.TIME_SIZE_JITTERED:
        return config.time_size_jittered_start_offset_seconds
    raise ValueError(f"Unsupported generation scenario: {scenario}")
