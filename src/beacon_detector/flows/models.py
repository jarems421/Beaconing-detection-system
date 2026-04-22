from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from beacon_detector.data.types import ProtocolType, TrafficEvent, TrafficLabel


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Fields used to group events into a flow."""

    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: ProtocolType
    src_port: str | None = None
    direction: str | None = None

    @classmethod
    def from_event(cls, event: TrafficEvent) -> FlowKey:
        return cls(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            protocol=event.protocol,
            src_port=event.src_port,
            direction=event.direction,
        )


@dataclass(frozen=True, slots=True)
class Flow:
    """Ordered traffic events belonging to one flow key."""

    flow_key: FlowKey
    events: tuple[TrafficEvent, ...]

    def __post_init__(self) -> None:
        if not self.events:
            raise ValueError("Flow must contain at least one event.")
        for event in self.events:
            if FlowKey.from_event(event) != self.flow_key:
                raise ValueError("All flow events must match the flow key.")

    @classmethod
    def from_events(cls, events: list[TrafficEvent]) -> Flow:
        if not events:
            raise ValueError("Cannot build a flow from an empty event list.")
        ordered_events = tuple(sorted(events, key=lambda event: event.timestamp))
        return cls(flow_key=FlowKey.from_event(ordered_events[0]), events=ordered_events)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def start_time(self) -> datetime:
        return self.events[0].timestamp

    @property
    def end_time(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def total_bytes(self) -> int:
        return sum(event.size_bytes for event in self.events)

    @property
    def label(self) -> TrafficLabel:
        """Return the flow label when all constituent events agree."""

        label_counts = self.label_counts
        if len(label_counts) > 1:
            raise ValueError("Mixed-label flows do not have a single safe label.")
        return self.events[0].label

    @property
    def label_counts(self) -> dict[TrafficLabel, int]:
        return dict(Counter(event.label for event in self.events))

    @property
    def has_mixed_labels(self) -> bool:
        return len(self.label_counts) > 1

    @property
    def scenario_names(self) -> tuple[str, ...]:
        """Return all scenario names represented by events in this flow."""

        return tuple(sorted({event.scenario_name for event in self.events}))
