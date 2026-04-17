"""Adapter for CTU-13 bidirectional NetFlow ``.binetflow`` files."""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from beacon_detector.data.types import ProtocolType, TrafficEvent, TrafficLabel

CTU13_REQUIRED_COLUMNS = (
    "StartTime",
    "Dur",
    "Proto",
    "SrcAddr",
    "Sport",
    "Dir",
    "DstAddr",
    "Dport",
    "State",
    "sTos",
    "dTos",
    "TotPkts",
    "TotBytes",
    "SrcBytes",
    "Label",
)

Ctu13MappedLabel = TrafficLabel | Literal["skip"]


@dataclass(frozen=True, slots=True)
class Ctu13LabelPolicy:
    """Explicit policy for reducing CTU-13's detailed labels to benign/beacon.

    CTU-13 documentation warns that ``To-Botnet`` and ``To-Normal`` labels should not be
    treated as malicious or benign by default. Background traffic is also ambiguous, so the
    default policy excludes it from the first external validation.
    """

    include_background_as_benign: bool = False
    include_to_normal_as_benign: bool = False
    include_to_botnet_as_beacon: bool = False


@dataclass(frozen=True, slots=True)
class Ctu13FlowRecord:
    start_time: datetime
    duration_seconds: float
    protocol: ProtocolType
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: int
    state: str
    total_packets: int
    total_bytes: int
    src_bytes: int
    raw_label: str
    mapped_label: TrafficLabel
    label_category: str


@dataclass(frozen=True, slots=True)
class Ctu13ParseSummary:
    source_path: str
    scenario_name: str
    total_rows: int
    parsed_events: int
    skipped_rows: int
    raw_label_counts: dict[str, int] = field(default_factory=dict)
    mapped_label_counts: dict[str, int] = field(default_factory=dict)
    skip_reason_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Ctu13LoadResult:
    records: tuple[Ctu13FlowRecord, ...]
    events: tuple[TrafficEvent, ...]
    summary: Ctu13ParseSummary


def load_ctu13_binetflow_events(
    path: str | Path,
    *,
    scenario_name: str,
    label_policy: Ctu13LabelPolicy | None = None,
    max_rows: int | None = None,
) -> Ctu13LoadResult:
    """Load CTU-13 bidirectional flow rows as project ``TrafficEvent`` records.

    Each CTU-13 bidirectional NetFlow row is treated as one connection-level event. The
    existing project flow builder can then group repeated CTU flow records by
    ``src_ip, dst_ip, dst_port, protocol`` and extract timing/size behaviour between
    repeated records.
    """

    source_path = Path(path)
    label_policy = label_policy or Ctu13LabelPolicy()
    records: list[Ctu13FlowRecord] = []
    events: list[TrafficEvent] = []
    raw_label_counts: Counter[str] = Counter()
    mapped_label_counts: Counter[str] = Counter()
    skip_reason_counts: Counter[str] = Counter()

    with source_path.open("r", encoding="utf-8", errors="replace", newline="") as input_file:
        reader = csv.DictReader(input_file)
        _validate_columns(reader.fieldnames or ())
        total_rows = 0
        for row in reader:
            if max_rows is not None and total_rows >= max_rows:
                break
            total_rows += 1
            raw_label = (row.get("Label") or "").strip()
            raw_label_counts[raw_label] += 1
            mapped_label = map_ctu13_label(raw_label, label_policy)
            if mapped_label == "skip":
                skip_reason_counts[f"label:{_label_category(raw_label)}"] += 1
                continue

            record = _record_from_row(row, mapped_label=mapped_label)
            if record is None:
                skip_reason_counts["invalid_or_unsupported_schema_value"] += 1
                continue

            records.append(record)
            mapped_label_counts[mapped_label] += 1
            events.append(
                TrafficEvent(
                    timestamp=record.start_time,
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    dst_port=record.dst_port,
                    protocol=record.protocol,
                    size_bytes=record.total_bytes,
                    label=record.mapped_label,
                    scenario_name=f"{scenario_name}:{record.label_category}",
                )
            )

    summary = Ctu13ParseSummary(
        source_path=str(source_path),
        scenario_name=scenario_name,
        total_rows=total_rows,
        parsed_events=len(events),
        skipped_rows=total_rows - len(events),
        raw_label_counts=dict(raw_label_counts),
        mapped_label_counts=dict(mapped_label_counts),
        skip_reason_counts=dict(skip_reason_counts),
    )
    return Ctu13LoadResult(records=tuple(records), events=tuple(events), summary=summary)


def map_ctu13_label(
    raw_label: str,
    label_policy: Ctu13LabelPolicy | None = None,
) -> Ctu13MappedLabel:
    label_policy = label_policy or Ctu13LabelPolicy()
    normalized = raw_label.lower()

    if "from-botnet" in normalized:
        return "beacon"
    if "from-normal" in normalized:
        return "benign"
    if "to-botnet" in normalized:
        return "beacon" if label_policy.include_to_botnet_as_beacon else "skip"
    if "to-normal" in normalized:
        return "benign" if label_policy.include_to_normal_as_benign else "skip"
    if "background" in normalized:
        return "benign" if label_policy.include_background_as_benign else "skip"
    return "skip"


def ctu13_feature_transfer_summary() -> list[dict[str, str]]:
    """Describe how CTU-13 rows transfer into the existing feature representation."""

    return [
        {
            "feature_group": "flow identity",
            "transfer_status": "direct",
            "notes": "SrcAddr, DstAddr, Dport, and Proto map to the existing FlowKey.",
        },
        {
            "feature_group": "event_count",
            "transfer_status": "derived_from_repeated_flow_records",
            "notes": (
                "Counts repeated CTU-13 bidirectional flow records sharing the project "
                "flow key; it is not CTU TotPkts."
            ),
        },
        {
            "feature_group": "flow_duration_seconds",
            "transfer_status": "derived_from_record_start_times",
            "notes": (
                "Duration is the span between first and last CTU flow-record start times "
                "inside the grouped project flow."
            ),
        },
        {
            "feature_group": "timing_features",
            "transfer_status": "derived_from_record_start_times",
            "notes": (
                "Inter-arrival statistics use gaps between CTU bidirectional flow records, "
                "not packet-level inter-arrival times."
            ),
        },
        {
            "feature_group": "size_features",
            "transfer_status": "derived_from_totbytes",
            "notes": "Size statistics use CTU TotBytes per bidirectional flow record.",
        },
        {
            "feature_group": "burst_features",
            "transfer_status": "derived_from_record_start_times",
            "notes": "Bursts describe clusters of CTU flow-record starts, not packet bursts.",
        },
        {
            "feature_group": "ctu_duration_totpkts_srcbytes",
            "transfer_status": "not_used_in_current_detectors",
            "notes": (
                "Dur, TotPkts, and SrcBytes are parsed for auditability but are not added "
                "to FlowFeatures in this step to avoid changing detector logic."
            ),
        },
    ]


def _record_from_row(
    row: dict[str, str],
    *,
    mapped_label: TrafficLabel,
) -> Ctu13FlowRecord | None:
    protocol = _parse_protocol(row.get("Proto", ""))
    dst_port = _parse_port(row.get("Dport", ""))
    start_time = _parse_start_time(row.get("StartTime", ""))
    duration = _parse_float(row.get("Dur", ""))
    total_packets = _parse_int(row.get("TotPkts", ""))
    total_bytes = _parse_int(row.get("TotBytes", ""))
    src_bytes = _parse_int(row.get("SrcBytes", ""))

    if (
        protocol is None
        or dst_port is None
        or start_time is None
        or duration is None
        or total_packets is None
        or total_bytes is None
        or src_bytes is None
    ):
        return None
    if total_bytes < 0 or total_packets < 0:
        return None

    raw_label = (row.get("Label") or "").strip()
    return Ctu13FlowRecord(
        start_time=start_time,
        duration_seconds=duration,
        protocol=protocol,
        src_ip=(row.get("SrcAddr") or "").strip(),
        src_port=(row.get("Sport") or "").strip(),
        direction=(row.get("Dir") or "").strip(),
        dst_ip=(row.get("DstAddr") or "").strip(),
        dst_port=dst_port,
        state=(row.get("State") or "").strip(),
        total_packets=total_packets,
        total_bytes=total_bytes,
        src_bytes=src_bytes,
        raw_label=raw_label,
        mapped_label=mapped_label,
        label_category=_label_category(raw_label),
    )


def _validate_columns(fieldnames: tuple[str, ...] | list[str]) -> None:
    missing = [column for column in CTU13_REQUIRED_COLUMNS if column not in fieldnames]
    if missing:
        raise ValueError(f"CTU-13 file is missing required columns: {missing}")


def _parse_start_time(value: str) -> datetime | None:
    value = value.strip()
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_protocol(value: str) -> ProtocolType | None:
    normalized = value.strip().lower()
    if normalized in {"tcp", "udp"}:
        return normalized  # type: ignore[return-value]
    return None


def _parse_port(value: str) -> int | None:
    normalized = value.strip().lower()
    if not normalized or normalized in {"nan", "none", "-"}:
        return None

    service_ports = {
        "http": 80,
        "https": 443,
        "domain": 53,
        "dns": 53,
        "ntp": 123,
        "smtp": 25,
        "imap": 143,
        "pop3": 110,
    }
    if normalized in service_ports:
        return service_ports[normalized]

    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _parse_int(value: str) -> int | None:
    parsed = _parse_float(value)
    if parsed is None:
        return None
    return int(parsed)


def _parse_float(value: str) -> float | None:
    normalized = value.strip()
    if not normalized or normalized.lower() in {"nan", "none", "-"}:
        return None
    try:
        return float(normalized)
    except ValueError:
        return None


def _label_category(raw_label: str) -> str:
    normalized = raw_label.strip()
    if normalized.startswith("flow="):
        normalized = normalized[len("flow=") :]
    if normalized.lower().startswith("from-botnet"):
        return "ctu13_from_botnet"
    if normalized.lower().startswith("to-botnet"):
        return "ctu13_to_botnet"
    if normalized.lower().startswith("from-normal"):
        return "ctu13_from_normal"
    if normalized.lower().startswith("to-normal"):
        return "ctu13_to_normal"
    if normalized.lower().startswith("background"):
        return "ctu13_background"
    return "ctu13_unknown"
