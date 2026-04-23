from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .schema import OperationalEvent, load_normalized_csv

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
    "src",
)
DST_IP_COLUMNS = (
    "dst_ip",
    "destination_ip",
    "dstaddr",
    "dst_addr",
    "destinationipv4address",
    "destinationipv6address",
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
    "flow_duration_seconds",
    "elapsed",
)


def load_operational_events(
    path: str | Path,
    *,
    input_format: OperationalInputFormat,
) -> list[OperationalEvent]:
    if input_format == "normalized-csv":
        return load_normalized_csv(path)
    if input_format == "zeek-conn":
        return load_zeek_conn_log(path)
    if input_format == "netflow-ipfix-csv":
        return load_netflow_ipfix_csv(path)
    raise ValueError(f"Unsupported operational input format: {input_format}")


def load_zeek_conn_log(path: str | Path) -> list[OperationalEvent]:
    fields: list[str] | None = None
    events: list[OperationalEvent] = []

    with Path(path).open("r", encoding="utf-8", errors="replace") as input_file:
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
            event = _event_from_zeek_row(row)
            if event is not None:
                events.append(event)

    return events


def load_netflow_ipfix_csv(path: str | Path) -> list[OperationalEvent]:
    events: list[OperationalEvent] = []
    with Path(path).open("r", encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        if not reader.fieldnames:
            raise ValueError("NetFlow/IPFIX CSV is missing a header row.")
        for row_number, row in enumerate(reader, start=2):
            event = _event_from_netflow_ipfix_row(row, row_number=row_number)
            if event is not None:
                events.append(event)
    return events


def _event_from_zeek_row(row: dict[str, str]) -> OperationalEvent | None:
    proto = _optional(row.get("proto"))
    if proto not in {"tcp", "udp"}:
        return None

    dst_port = _parse_port(_required(row, "id.resp_p"), "id.resp_p")
    total_bytes = _parse_zeek_int(row.get("orig_bytes")) + _parse_zeek_int(
        row.get("resp_bytes")
    )
    total_packets = _parse_zeek_int(row.get("orig_pkts")) + _parse_zeek_int(
        row.get("resp_pkts")
    )
    timestamp = datetime.fromtimestamp(float(_required(row, "ts")), tz=timezone.utc)

    return OperationalEvent(
        timestamp=timestamp,
        src_ip=_required(row, "id.orig_h"),
        src_port=_parse_optional_port_text(row.get("id.orig_p"), "id.orig_p"),
        direction="->",
        dst_ip=_required(row, "id.resp_h"),
        dst_port=dst_port,
        protocol=proto,  # type: ignore[arg-type]
        total_bytes=total_bytes,
        duration_seconds=_parse_zeek_float(row.get("duration")),
        total_packets=total_packets,
    )


def _event_from_netflow_ipfix_row(
    row: dict[str, str],
    *,
    row_number: int,
) -> OperationalEvent | None:
    proto = _parse_flow_protocol(_required_alias(row, PROTOCOL_COLUMNS, row_number))
    if proto is None:
        return None

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

    return OperationalEvent(
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


def _parse_zeek_int(value: str | None) -> int:
    value = _optional(value)
    if value is None:
        return 0
    return int(value)


def _parse_zeek_float(value: str | None) -> float | None:
    value = _optional(value)
    if value is None:
        return None
    return float(value)


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


def _parse_flow_duration(
    value: str | None,
    start_timestamp: datetime,
    end_timestamp: datetime | None,
) -> float | None:
    value = _optional(value)
    if value is not None:
        duration = float(value)
        if duration < 0:
            raise ValueError("duration_seconds must be non-negative.")
        return duration
    if end_timestamp is None:
        return None
    duration = (end_timestamp - start_timestamp).total_seconds()
    return max(0.0, duration)
