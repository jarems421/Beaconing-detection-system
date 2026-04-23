from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

ProtocolName = Literal["tcp", "udp"]

NORMALIZED_REQUIRED_COLUMNS = (
    "timestamp",
    "src_ip",
    "direction",
    "dst_ip",
    "dst_port",
    "protocol",
    "total_bytes",
)
NORMALIZED_OPTIONAL_COLUMNS = (
    "src_port",
    "duration_seconds",
    "total_packets",
)
SUPPORTED_PROTOCOLS = {"tcp", "udp"}


@dataclass(frozen=True, slots=True)
class OperationalEvent:
    """Canonical operational input record.

    Each row is a connection or flow-log event. Repeated events with the same
    operational grouping key are aggregated into behaviour features.
    """

    timestamp: datetime
    src_ip: str
    direction: str
    dst_ip: str
    dst_port: int
    protocol: ProtocolName
    total_bytes: int
    src_port: str | None = None
    duration_seconds: float | None = None
    total_packets: int | None = None


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    row_number: int | None
    column: str | None
    message: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    input_path: Path
    row_count: int
    valid_row_count: int
    issues: tuple[ValidationIssue, ...]

    @property
    def is_valid(self) -> bool:
        return not self.issues


def validate_normalized_csv(path: str | Path) -> ValidationResult:
    input_path = Path(path)
    issues: list[ValidationIssue] = []
    row_count = 0
    valid_row_count = 0

    with input_path.open("r", encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        fieldnames = reader.fieldnames or []
        missing_columns = [
            column for column in NORMALIZED_REQUIRED_COLUMNS if column not in fieldnames
        ]
        for column in missing_columns:
            issues.append(
                ValidationIssue(
                    row_number=None,
                    column=column,
                    message=f"Missing required column: {column}",
                )
            )
        if missing_columns:
            return ValidationResult(input_path, row_count, valid_row_count, tuple(issues))

        for row_number, row in enumerate(reader, start=2):
            row_count += 1
            try:
                event_from_normalized_row(row)
            except ValueError as exc:
                issues.append(
                    ValidationIssue(
                        row_number=row_number,
                        column=None,
                        message=str(exc),
                    )
                )
                continue
            valid_row_count += 1

    return ValidationResult(input_path, row_count, valid_row_count, tuple(issues))


def load_normalized_csv(path: str | Path) -> list[OperationalEvent]:
    validation = validate_normalized_csv(path)
    if not validation.is_valid:
        first_issue = validation.issues[0]
        location = (
            f"row {first_issue.row_number}"
            if first_issue.row_number is not None
            else "header"
        )
        raise ValueError(f"Invalid normalized CSV at {location}: {first_issue.message}")

    with Path(path).open("r", encoding="utf-8", newline="") as input_file:
        return [event_from_normalized_row(row) for row in csv.DictReader(input_file)]


def event_from_normalized_row(row: dict[str, str]) -> OperationalEvent:
    timestamp = _parse_timestamp(_required(row, "timestamp"))
    src_ip = _required(row, "src_ip")
    direction = _required(row, "direction")
    dst_ip = _required(row, "dst_ip")
    dst_port = _parse_port(_required(row, "dst_port"), "dst_port")
    protocol = _parse_protocol(_required(row, "protocol"))
    total_bytes = _parse_int(_required(row, "total_bytes"), "total_bytes")
    if total_bytes < 0:
        raise ValueError("total_bytes must be non-negative.")

    total_packets = _parse_optional_int(row.get("total_packets"), "total_packets")
    if total_packets is not None and total_packets < 0:
        raise ValueError("total_packets must be non-negative.")

    duration_seconds = _parse_optional_float(
        row.get("duration_seconds"),
        "duration_seconds",
    )
    if duration_seconds is not None and duration_seconds < 0:
        raise ValueError("duration_seconds must be non-negative.")

    return OperationalEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=_parse_optional_port_text(row.get("src_port"), "src_port"),
        direction=direction,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        total_bytes=total_bytes,
        duration_seconds=duration_seconds,
        total_packets=total_packets,
    )


def _required(row: dict[str, str], column: str) -> str:
    value = (row.get(column) or "").strip()
    if not value:
        raise ValueError(f"{column} is required.")
    return value


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_timestamp(value: str) -> datetime:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"timestamp is not ISO-8601: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_protocol(value: str) -> ProtocolName:
    normalized = value.lower()
    if normalized not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Unsupported protocol: {value}")
    return normalized  # type: ignore[return-value]


def _parse_int(value: str, column: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{column} must be an integer.") from exc


def _parse_port(value: str, column: str) -> int:
    port = _parse_int(value, column)
    if port < 0 or port > 65535:
        raise ValueError(f"{column} must be between 0 and 65535.")
    return port


def _parse_optional_port_text(value: str | None, column: str) -> str | None:
    value = _optional_text(value)
    if value is None:
        return None
    return str(_parse_port(value, column))


def _parse_optional_int(value: str | None, column: str) -> int | None:
    value = _optional_text(value)
    if value is None:
        return None
    return _parse_int(value, column)


def _parse_optional_float(value: str | None, column: str) -> float | None:
    value = _optional_text(value)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{column} must be numeric.") from exc
