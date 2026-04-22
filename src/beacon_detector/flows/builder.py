from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from beacon_detector.data import CsvTrafficDataLoader
from beacon_detector.data.types import TrafficEvent

from .models import Flow, FlowKey


def build_flows(events: Iterable[TrafficEvent]) -> list[Flow]:
    grouped_events: dict[FlowKey, list[TrafficEvent]] = defaultdict(list)
    for event in events:
        grouped_events[FlowKey.from_event(event)].append(event)

    flows = [Flow.from_events(group_events) for group_events in grouped_events.values()]
    return sorted(
        flows,
        key=lambda flow: (
            flow.start_time,
            flow.flow_key.src_ip,
            flow.flow_key.src_port or "",
            flow.flow_key.direction or "",
            flow.flow_key.dst_ip,
        ),
    )


def load_flows_from_csv(path: str | Path) -> list[Flow]:
    events = CsvTrafficDataLoader().load(path)
    return build_flows(events)
