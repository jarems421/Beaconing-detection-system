from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from beacon_detector.data import (
    SyntheticTrafficConfig,
    TrafficEvent,
    generate_combined_synthetic_dataset,
)

SYNTHETIC_NORMALIZED_COLUMNS = [
    "timestamp",
    "src_ip",
    "src_port",
    "direction",
    "dst_ip",
    "dst_port",
    "protocol",
    "total_bytes",
    "duration_seconds",
    "total_packets",
    "label",
    "scenario_name",
]


@dataclass(frozen=True, slots=True)
class SyntheticNormalizedExportResult:
    output_csv: Path
    metadata_json: Path
    event_count: int
    benign_event_count: int
    beacon_event_count: int


def export_synthetic_normalized_csv(
    *,
    output_path: str | Path,
    config: SyntheticTrafficConfig | None = None,
    include_time_size_jitter: bool = True,
    metadata_path: str | Path | None = None,
) -> SyntheticNormalizedExportResult:
    config = config or SyntheticTrafficConfig(
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    events = generate_combined_synthetic_dataset(
        config,
        include_time_size_jitter=include_time_size_jitter,
    )

    output_csv = Path(output_path)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=SYNTHETIC_NORMALIZED_COLUMNS)
        writer.writeheader()
        writer.writerows(_normalized_row(event) for event in events)

    metadata_json = (
        Path(metadata_path)
        if metadata_path is not None
        else output_csv.with_suffix(".metadata.json")
    )
    metadata_json.parent.mkdir(parents=True, exist_ok=True)
    metadata = _metadata(
        config=config,
        events=events,
        output_csv=output_csv,
        include_time_size_jitter=include_time_size_jitter,
    )
    metadata_json.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return SyntheticNormalizedExportResult(
        output_csv=output_csv,
        metadata_json=metadata_json,
        event_count=len(events),
        benign_event_count=sum(1 for event in events if event.label == "benign"),
        beacon_event_count=sum(1 for event in events if event.label == "beacon"),
    )


def _normalized_row(event: TrafficEvent) -> dict[str, str | int]:
    return {
        "timestamp": event.timestamp.isoformat(),
        "src_ip": event.src_ip,
        "src_port": event.src_port or "",
        "direction": event.direction or "->",
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "total_bytes": event.size_bytes,
        "duration_seconds": "",
        "total_packets": "",
        "label": event.label,
        "scenario_name": event.scenario_name,
    }


def _metadata(
    *,
    config: SyntheticTrafficConfig,
    events: list[TrafficEvent],
    output_csv: Path,
    include_time_size_jitter: bool,
) -> dict[str, Any]:
    scenario_counts: dict[str, int] = {}
    for event in events:
        scenario_counts[event.scenario_name] = (
            scenario_counts.get(event.scenario_name, 0) + 1
        )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "output_csv": str(output_csv),
        "input_contract": "normalized_csv_with_label",
        "source": "synthetic_generator",
        "include_time_size_jitter": include_time_size_jitter,
        "event_count": len(events),
        "benign_event_count": sum(1 for event in events if event.label == "benign"),
        "beacon_event_count": sum(1 for event in events if event.label == "beacon"),
        "scenario_counts": dict(sorted(scenario_counts.items())),
        "columns": SYNTHETIC_NORMALIZED_COLUMNS,
        "config": _jsonable(asdict(config)),
        "notes": [
            "This is a bootstrap/demo dataset exported into the operational schema.",
            "Synthetic-trained models should not be treated as deployment-ready.",
        ],
    }


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value
