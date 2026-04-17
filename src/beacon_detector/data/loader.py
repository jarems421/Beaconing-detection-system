from __future__ import annotations

import csv
from pathlib import Path
from typing import Protocol

from .types import ProtocolType, TrafficEvent, TrafficLabel

CSV_FIELDS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "size_bytes",
    "label",
    "scenario_name",
)


class TrafficDataLoader(Protocol):
    def load(self, path: str | Path) -> list[TrafficEvent]:
        ...


class CsvTrafficDataLoader:
    def load(self, path: str | Path) -> list[TrafficEvent]:
        file_path = Path(path)
        events: list[TrafficEvent] = []
        with file_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                events.append(
                    TrafficEvent.from_iso_timestamp(
                        timestamp=row["timestamp"],
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        dst_port=int(row["dst_port"]),
                        protocol=_parse_protocol(row["protocol"]),
                        size_bytes=int(row["size_bytes"]),
                        label=_parse_label(row["label"]),
                        scenario_name=row.get("scenario_name") or "unknown",
                    )
                )
        return events


def save_events_to_csv(events: list[TrafficEvent], path: str | Path) -> Path:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "timestamp": event.timestamp.isoformat(),
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                    "size_bytes": event.size_bytes,
                    "label": event.label,
                    "scenario_name": event.scenario_name,
                }
            )
    return file_path


def _parse_protocol(raw: str) -> ProtocolType:
    lowered = raw.strip().lower()
    if lowered in ("tcp", "udp"):
        return lowered
    raise ValueError(f"Unsupported protocol value: {raw}")


def _parse_label(raw: str) -> TrafficLabel:
    lowered = raw.strip().lower()
    if lowered in ("benign", "beacon"):
        return lowered
    raise ValueError(f"Unsupported label value: {raw}")
