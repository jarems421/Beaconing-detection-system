from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

ProtocolType = Literal["tcp", "udp"]
TrafficLabel = Literal["benign", "beacon"]


@dataclass(frozen=True, slots=True)
class TrafficEvent:
    """Single traffic event used as input to flow construction."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: ProtocolType
    size_bytes: int
    label: TrafficLabel
    scenario_name: str = "unknown"

    @staticmethod
    def from_iso_timestamp(
        *,
        timestamp: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: ProtocolType,
        size_bytes: int,
        label: TrafficLabel,
        scenario_name: str = "unknown",
    ) -> "TrafficEvent":
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return TrafficEvent(
            timestamp=parsed,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            size_bytes=size_bytes,
            label=label,
            scenario_name=scenario_name,
        )


PacketEvent = TrafficEvent
