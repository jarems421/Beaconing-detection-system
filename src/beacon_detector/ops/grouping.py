from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from beacon_detector.data.types import TrafficEvent, TrafficLabel
from beacon_detector.flows import Flow, FlowKey, build_flows

from .schema import OperationalEvent

OperationalLabelPolicy = Literal["benign", "event"]


@dataclass(frozen=True, slots=True)
class OpsFlowContext:
    source_ports_by_key: dict[FlowKey, tuple[str, ...]]


def build_operational_flows(
    events: list[OperationalEvent],
    *,
    label_policy: OperationalLabelPolicy = "benign",
) -> tuple[list[Flow], OpsFlowContext]:
    source_ports_by_key: dict[FlowKey, set[str]] = {}
    traffic_events: list[TrafficEvent] = []
    for event in events:
        key = FlowKey(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            protocol=event.protocol,
            direction=event.direction,
            src_port=None,
        )
        if event.src_port:
            source_ports_by_key.setdefault(key, set()).add(event.src_port)
        traffic_events.append(
            TrafficEvent(
                timestamp=event.timestamp,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                protocol=event.protocol,
                size_bytes=event.total_bytes,
                label=_traffic_label(event, label_policy),
                scenario_name="operational",
                src_port=None,
                direction=event.direction,
            )
        )

    context = OpsFlowContext(
        source_ports_by_key={
            key: tuple(sorted(source_ports))
            for key, source_ports in source_ports_by_key.items()
        }
    )
    return build_flows(traffic_events), context


def _traffic_label(
    event: OperationalEvent,
    label_policy: OperationalLabelPolicy,
) -> TrafficLabel:
    if label_policy == "benign":
        return "benign"
    if event.label in {"benign", "beacon"}:
        return event.label
    raise ValueError("Training events must be labelled benign or beacon.")
