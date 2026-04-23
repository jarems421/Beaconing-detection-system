from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .schema import OperationalEvent, load_normalized_csv, validate_normalized_csv

OperationalInputFormat = Literal["normalized-csv", "zeek-conn", "netflow-ipfix-csv"]

TIMESTAMP_COLUMNS = (
    "timestamp",
    "start_time",
    "flow_start",
    "flowstart",
    "flowstartseconds",
    "flowstartmilliseconds",
    "first_switched",
    "firstswitched",
    "first",
    "start",
)
END_TIMESTAMP_COLUMNS = (
    "end_time",
    "flow_end",
    "flowend",
    "flowendseconds",
    "flowendmilliseconds",
    "last_switched",
    "lastswitched",
    "last",
    "end",
)
SRC_IP_COLUMNS = (
    "src_ip",
    "source_ip",
    "srcaddr",
    "src_addr",
    "sourceipv4address",
    "sourceipv6address",
    "sourceaddress",
    "src",
)
DST_IP_COLUMNS = (
    "dst_ip",
    "destination_ip",
    "dstaddr",
    "dst_addr",
    "destinationipv4address",
    "destinationipv6address",
    "destinationaddress",
    "dst",
)
SRC_PORT_COLUMNS = (
    "src_port",
    "source_port",
    "srcport",
    "sourceport",
    "spt",
    "sport",
    "s_port",
    "sourcedport",
    "sourcetransportport",
)
DST_PORT_COLUMNS = (
    "dst_port",
    "destination_port",
    "dstport",
    "destinationport",
    "dpt",
    "dport",
    "d_port",
    "destinationtransportport",
)
PROTOCOL_COLUMNS = (
    "protocol",
    "proto",
    "protocolidentifier",
    "transportprotocol",
    "ipprotocol",
    "prot",
)
BYTES_COLUMNS = (
    "total_bytes",
    "bytes",
    "octets",
    "in_bytes",
    "numbytes",
    "bytestotal",
    "octetdeltacount",
    "octettotalcount",
)
PACKETS_COLUMNS = (
    "total_packets",
    "packets",
    "pkts",
    "in_pkts",
    "numpackets",
    "packetdeltacount",
    "packettotalcount",
)
DURATION_COLUMNS = (
    "duration_seconds",
    "duration",
    "dur",
    "durationsecs",
    "flow_duration_seconds",
    "elapsed",
)


@dataclass(frozen=True, slots=True)
class OperationalIngestDiagnostics:
    input_path: Path
    input_format: OperationalInputFormat
    input_row_count: int
    loaded_event_count: int
    skipped_row_count: int
    skipped_row_reasons: dict[str, int]


@dataclass(frozen=True, slots=True)
class OperationalLoadResult:
    events: list[OperationalEvent]
    diagnostics: OperationalIngestDiagnostics


def load_operational_input(
    path: str | Path,
    *,
    input_format: OperationalInputFormat,
) -> OperationalLoadResult:
    if input_format == "normalized-csv":
        return _load_normalized_csv_result(path)
    if input_format == "zeek-conn":
        return _load_zeek_conn_log_result(path)
    if input_format == "netflow-ipfix-csv":
        return _load_netflow_ipfix_csv_result(path)
    raise ValueError(f"Unsupported operational input format: {input_format}")


def load_operational_events(
    path: str | Path,
    *,
    input_format: OperationalInputFormat,
) -> list[OperationalEvent]:
    return load_operational_input(path, input_format=input_format).events


def load_zeek_conn_log(path: str | Path) -> list[OperationalEvent]:
    return _load_zeek_conn_log_result(path).events


def load_netflow_ipfix_csv(path: str | Path) -> list[OperationalEvent]:
    return _load_netflow_ipfix_csv_result(path).events


def _load_normalized_csv_result(path: str | Path) -> OperationalLoadResult:
    input_path = Path(path)
    validation = validate_normalized_csv(input_path)
    if not validation.is_valid:
        first_issue = validation.issues[0]
        location = (
            f"row {first_issue.row_number}"
            if first_issue.row_number is not None
            else "header"
        )
        raise ValueError(
            f"Invalid normalized CSV at {location}: {first_issue.message}"
        )
    if validation.row_count == 0:
        raise ValueError("Normalized CSV contains no data rows.")
    events = load_normalized_csv(input_path)
    return OperationalLoadResult(
        events=events,
        diagnostics=_diagnostics(
            input_path=input_path,
            input_format="normalized-csv",
            input_row_count=validation.row_count,
            loaded_event_count=len(events),
            skipped_row_reasons={},
        ),
    )


def _load_zeek_conn_log_result(path: str | Path) -> OperationalLoadResult:
    input_path = Path(path)
    fields: list[str] | None = None
    events: list[OperationalEvent] = []
    skipped_row_reasons: Counter[str] = Counter()
    input_row_count = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as input_file:
        for line in input_file:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                raise ValueError("Zeek conn.log is missing a #fields header.")

            values = line.split("\t")
            row = dict(zip(fields, values, strict=False))
            input_row_count += 1
            try:
                event, skip_reason = _event_from_zeek_row(row)
            except ValueError as exc:
                raise ValueError(
                    f"Zeek conn.log row {input_row_count}: {exc}"
                ) from exc
            if skip_reason is not None:
                skipped_row_reasons[skip_reason] += 1
                continue
            if event is not None:
                events.append(event)

    if input_row_count == 0:
        raise ValueError("Zeek conn.log contains no data rows.")

    return OperationalLoadResult(
        events=events,
        diagnostics=_diagnostics(
            input_path=input_path,
            input_format="zeek-conn",
            input_row_count=input_row_count,
            loaded_event_count=len(events),
            skipped_row_reasons=dict(skipped_row_reasons),
        ),
    )


def _load_netflow_ipfix_csv_result(path: str | Path) -> OperationalLoadResult:
    input_path = Path(path)
    events: list[OperationalEvent] = []
    skipped_row_reasons: Counter[str] = Counter()
    input_row_count = 0

    with input_path.open("r", encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        if not reader.fieldnames:
            raise ValueError("NetFlow/IPFIX CSV is missing a header row.")
        for row_number, row in enumerate(reader, start=2):
            input_row_count += 1
            try:
                event, skip_reason = _event_from_netflow_ipfix_row(
                    row,
                    row_number=row_number,
                )
            except ValueError as exc:
                message = str(exc)
                if not message.startswith("NetFlow/IPFIX CSV row "):
                    message = f"NetFlow/IPFIX CSV row {row_number}: {message}"
                raise ValueError(message) from exc
            if skip_reason is not None:
                skipped_row_reasons[skip_reason] += 1
                continue
            if event is not None:
                events.append(event)
    if input_row_count == 0:
        raise ValueError("NetFlow/IPFIX CSV contains no data rows.")
    return OperationalLoadResult(
        events=events,
        diagnostics=_diagnostics(
            input_path=input_path,
            input_format="netflow-ipfix-csv",
            input_row_count=input_row_count,
            loaded_event_count=len(events),
            skipped_row_reasons=dict(skipped_row_reasons),
        ),
    )


def _event_from_zeek_row(
    row: dict[str, str],
) -> tuple[OperationalEvent | None, str | None]:
    proto = _required(row, "proto").lower()
    if proto not in {"tcp", "udp"}:
        return None, "unsupported_protocol"

    dst_port = _parse_port(_required(row, "id.resp_p"), "id.resp_p")
    total_bytes = _parse_zeek_int(row.get("orig_bytes"), "orig_bytes") + _parse_zeek_int(
        row.get("resp_bytes"),
        "resp_bytes",
    )
    total_packets = _parse_zeek_int(row.get("orig_pkts"), "orig_pkts") + _parse_zeek_int(
        row.get("resp_pkts"),
        "resp_pkts",
    )
    timestamp = _parse_zeek_timestamp(_required(row, "ts"), "ts")

    return (
        OperationalEvent(
            timestamp=timestamp,
            src_ip=_required(row, "id.orig_h"),
            src_port=_parse_optional_port_text(row.get("id.orig_p"), "id.orig_p"),
            direction="->",
            dst_ip=_required(row, "id.resp_h"),
            dst_port=dst_port,
            protocol=proto,  # type: ignore[arg-type]
            total_bytes=total_bytes,
            duration_seconds=_parse_zeek_float(row.get("duration"), "duration"),
            total_packets=total_packets,
        ),
        None,
    )


def _event_from_netflow_ipfix_row(
    row: dict[str, str],
    *,
    row_number: int,
) -> tuple[OperationalEvent | None, str | None]:
    proto = _parse_flow_protocol(_required_alias(row, PROTOCOL_COLUMNS, row_number))
    if proto is None:
        return None, "unsupported_protocol"

    timestamp_value, timestamp_column = _required_alias_with_column(
        row,
        TIMESTAMP_COLUMNS,
        row_number,
    )
    timestamp = _parse_flow_timestamp(timestamp_value, timestamp_column)
    end_value = _optional_alias(row, END_TIMESTAMP_COLUMNS)
    end_timestamp = (
        _parse_flow_timestamp(end_value[0], end_value[1])
        if end_value is not None
        else None
    )
    duration_seconds = _parse_flow_duration(
        _optional_alias_value(row, DURATION_COLUMNS),
        timestamp,
        end_timestamp,
    )

    return (
        OperationalEvent(
            timestamp=timestamp,
            src_ip=_required_alias(row, SRC_IP_COLUMNS, row_number),
            src_port=_parse_optional_port_text(
                _optional_alias_value(row, SRC_PORT_COLUMNS),
                "src_port",
            ),
            direction="->",
            dst_ip=_required_alias(row, DST_IP_COLUMNS, row_number),
            dst_port=_parse_port(
                _required_alias(row, DST_PORT_COLUMNS, row_number),
                "dst_port",
            ),
            protocol=proto,
            total_bytes=_parse_non_negative_int(
                _required_alias(row, BYTES_COLUMNS, row_number),
                "total_bytes",
            ),
            duration_seconds=duration_seconds,
            total_packets=_parse_optional_non_negative_int(
                _optional_alias_value(row, PACKETS_COLUMNS),
                "total_packets",
            ),
        ),
        None,
    )


def _required(row: dict[str, str], column: str) -> str:
    value = _optional(row.get(column))
    if value is None:
        raise ValueError(f"Zeek conn.log row is missing {column}.")
    return value


def _optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped in {"", "-", "(empty)"}:
        return None
    return stripped


def _parse_int(value: str, column: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{column} must be an integer.") from exc


def _parse_non_negative_int(value: str, column: str) -> int:
    parsed = _parse_int(value, column)
    if parsed < 0:
        raise ValueError(f"{column} must be non-negative.")
    return parsed


def _parse_optional_non_negative_int(value: str | None, column: str) -> int | None:
    value = _optional(value)
    if value is None:
        return None
    return _parse_non_negative_int(value, column)


def _parse_port(value: str, column: str) -> int:
    port = _parse_int(value, column)
    if port < 0 or port > 65535:
        raise ValueError(f"{column} must be between 0 and 65535.")
    return port


def _parse_optional_port_text(value: str | None, column: str) -> str | None:
    value = _optional(value)
    if value is None:
        return None
    return str(_parse_port(value, column))


def _parse_zeek_int(value: str | None, column: str) -> int:
    value = _optional(value)
    if value is None:
        return 0
    return _parse_int(value, column)


def _parse_zeek_float(value: str | None, column: str) -> float | None:
    value = _optional(value)
    if value is None:
        return None
    return _parse_float(value, column)


def _required_alias(
    row: dict[str, str],
    aliases: tuple[str, ...],
    row_number: int,
) -> str:
    value = _optional_alias_value(row, aliases)
    if value is None:
        raise ValueError(
            f"NetFlow/IPFIX CSV row {row_number} is missing one of: "
            f"{', '.join(aliases)}."
        )
    return value


def _required_alias_with_column(
    row: dict[str, str],
    aliases: tuple[str, ...],
    row_number: int,
) -> tuple[str, str]:
    value = _optional_alias(row, aliases)
    if value is None:
        raise ValueError(
            f"NetFlow/IPFIX CSV row {row_number} is missing one of: "
            f"{', '.join(aliases)}."
        )
    return value


def _optional_alias_value(
    row: dict[str, str],
    aliases: tuple[str, ...],
) -> str | None:
    value = _optional_alias(row, aliases)
    if value is None:
        return None
    return value[0]


def _optional_alias(
    row: dict[str, str],
    aliases: tuple[str, ...],
) -> tuple[str, str] | None:
    normalized = {_normalize_column_name(key): value for key, value in row.items()}
    for alias in aliases:
        column = _normalize_column_name(alias)
        value = _optional(normalized.get(column))
        if value is not None:
            return value, column
    return None


def _normalize_column_name(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _parse_flow_protocol(value: str) -> str | None:
    normalized = value.strip().lower()
    if normalized in {"tcp", "6"}:
        return "tcp"
    if normalized in {"udp", "17"}:
        return "udp"
    return None


def _parse_flow_timestamp(value: str, column: str) -> datetime:
    value = value.strip()
    try:
        numeric = float(value)
    except ValueError:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    if "millisecond" in column or numeric >= 1_000_000_000_000:
        numeric /= 1000.0
    return datetime.fromtimestamp(numeric, tz=timezone.utc)


def _parse_zeek_timestamp(value: str, column: str) -> datetime:
    numeric = _parse_float(value, column)
    return datetime.fromtimestamp(numeric, tz=timezone.utc)


def _parse_flow_duration(
    value: str | None,
    start_timestamp: datetime,
    end_timestamp: datetime | None,
) -> float | None:
    value = _optional(value)
    if value is not None:
        duration = _parse_float(value, "duration_seconds")
        if duration < 0:
            raise ValueError("duration_seconds must be non-negative.")
        return duration
    if end_timestamp is None:
        return None
    duration = (end_timestamp - start_timestamp).total_seconds()
    return max(0.0, duration)


def _parse_float(value: str, column: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{column} must be numeric.") from exc


def _diagnostics(
    *,
    input_path: Path,
    input_format: OperationalInputFormat,
    input_row_count: int,
    loaded_event_count: int,
    skipped_row_reasons: dict[str, int],
) -> OperationalIngestDiagnostics:
    return OperationalIngestDiagnostics(
        input_path=input_path,
        input_format=input_format,
        input_row_count=input_row_count,
        loaded_event_count=loaded_event_count,
        skipped_row_count=input_row_count - loaded_event_count,
        skipped_row_reasons=skipped_row_reasons,
    )
