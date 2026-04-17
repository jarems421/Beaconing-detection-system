"""CTU-13 native feature rows derived directly from bidirectional flow fields."""

from __future__ import annotations

from dataclasses import dataclass

from beacon_detector.data.types import TrafficLabel
from beacon_detector.parsing.ctu13 import Ctu13FlowRecord


@dataclass(frozen=True, slots=True)
class Ctu13NativeFeatures:
    """Feature row that matches CTU-13 bidirectional `.binetflow` records.

    This is intentionally separate from `FlowFeatures`. CTU-13 rows are already
    bidirectional flow summaries, so fields like `Dur`, `TotPkts`, and `SrcBytes`
    should be used directly rather than approximated through synthetic event-style
    grouping.
    """

    scenario_name: str
    label: TrafficLabel
    label_group: str
    protocol: str
    state: str
    dst_port: int
    service_bucket: str
    duration_seconds: float
    total_packets: int
    total_bytes: int
    src_bytes: int
    dst_bytes: int
    src_byte_ratio: float | None
    dst_byte_ratio: float | None
    packets_per_second: float | None
    bytes_per_second: float | None
    mean_packet_size_bytes: float | None
    src_bytes_per_packet: float | None
    dst_bytes_per_packet: float | None
    protocol_tcp: int
    protocol_udp: int
    is_web_port: int
    is_dns_port: int
    is_ntp_port: int
    is_ctu_common_port: int


CTU13_NATIVE_NUMERIC_FEATURES = (
    "duration_seconds",
    "total_packets",
    "total_bytes",
    "src_bytes",
    "dst_bytes",
    "src_byte_ratio",
    "dst_byte_ratio",
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size_bytes",
    "src_bytes_per_packet",
    "dst_bytes_per_packet",
    "dst_port",
    "protocol_tcp",
    "protocol_udp",
    "is_web_port",
    "is_dns_port",
    "is_ntp_port",
    "is_ctu_common_port",
)


def native_features_from_ctu13_record(
    record: Ctu13FlowRecord,
    *,
    scenario_name: str,
) -> Ctu13NativeFeatures:
    dst_bytes = max(0, record.total_bytes - record.src_bytes)
    total_bytes = max(0, record.total_bytes)
    total_packets = max(0, record.total_packets)
    duration = max(0.0, record.duration_seconds)

    return Ctu13NativeFeatures(
        scenario_name=scenario_name,
        label=record.mapped_label,
        label_group=record.label_category,
        protocol=record.protocol,
        state=record.state,
        dst_port=record.dst_port,
        service_bucket=service_bucket(record.dst_port),
        duration_seconds=duration,
        total_packets=total_packets,
        total_bytes=total_bytes,
        src_bytes=max(0, record.src_bytes),
        dst_bytes=dst_bytes,
        src_byte_ratio=_safe_divide(record.src_bytes, total_bytes),
        dst_byte_ratio=_safe_divide(dst_bytes, total_bytes),
        packets_per_second=_safe_divide(total_packets, duration),
        bytes_per_second=_safe_divide(total_bytes, duration),
        mean_packet_size_bytes=_safe_divide(total_bytes, total_packets),
        src_bytes_per_packet=_safe_divide(record.src_bytes, total_packets),
        dst_bytes_per_packet=_safe_divide(dst_bytes, total_packets),
        protocol_tcp=1 if record.protocol == "tcp" else 0,
        protocol_udp=1 if record.protocol == "udp" else 0,
        is_web_port=1 if record.dst_port in {80, 443, 8080, 8443} else 0,
        is_dns_port=1 if record.dst_port == 53 else 0,
        is_ntp_port=1 if record.dst_port == 123 else 0,
        is_ctu_common_port=1 if record.dst_port in {13363, 19083} else 0,
    )


def native_features_from_ctu13_records(
    records: list[Ctu13FlowRecord] | tuple[Ctu13FlowRecord, ...],
    *,
    scenario_name: str,
) -> list[Ctu13NativeFeatures]:
    return [
        native_features_from_ctu13_record(record, scenario_name=scenario_name)
        for record in records
    ]


def service_bucket(dst_port: int) -> str:
    if dst_port == 53:
        return "dns_53"
    if dst_port == 80:
        return "http_80"
    if dst_port == 123:
        return "ntp_123"
    if dst_port == 443:
        return "https_443"
    if dst_port in {13363, 19083}:
        return f"ctu_common_{dst_port}"
    if dst_port < 1024:
        return "other_well_known_0_1023"
    if dst_port < 49152:
        return "registered_1024_49151"
    return "ephemeral_49152_plus"


def _safe_divide(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator
