from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .schema import OperationalEvent, load_normalized_csv

OperationalInputFormat = Literal["normalized-csv", "zeek-conn"]


def load_operational_events(
    path: str | Path,
    *,
    input_format: OperationalInputFormat,
) -> list[OperationalEvent]:
    if input_format == "normalized-csv":
        return load_normalized_csv(path)
    if input_format == "zeek-conn":
        return load_zeek_conn_log(path)
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
