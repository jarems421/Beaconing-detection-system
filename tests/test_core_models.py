from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import TrafficEvent
from beacon_detector.features import FlowFeatures
from beacon_detector.flows import Flow, FlowKey


class TestCoreModels(unittest.TestCase):
    def test_traffic_event_from_iso_timestamp(self) -> None:
        event = TrafficEvent.from_iso_timestamp(
            timestamp="2026-01-01T00:00:00+00:00",
            src_ip="10.0.0.5",
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="tcp",
            size_bytes=120,
            label="beacon",
            scenario_name="fixed",
        )

        self.assertEqual(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.scenario_name, "fixed")

    def test_flow_orders_events_and_exposes_basic_properties(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        later = _event(timestamp=start + timedelta(seconds=30), size_bytes=140)
        first = _event(timestamp=start, size_bytes=100)

        flow = Flow.from_events([later, first])

        self.assertEqual(flow.flow_key, FlowKey.from_event(first))
        self.assertEqual(flow.event_count, 2)
        self.assertEqual(flow.duration_seconds, 30.0)
        self.assertEqual(flow.total_bytes, 240)
        self.assertEqual(flow.label, "beacon")

    def test_flow_features_can_represent_planned_feature_groups(self) -> None:
        flow_key = FlowKey(
            src_ip="10.0.0.5",
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="tcp",
        )
        features = FlowFeatures(
            flow_key=flow_key,
            label="beacon",
            scenario_name="jittered",
            event_count=10,
            total_bytes=1280,
            mean_interarrival_seconds=60.0,
            events_per_minute=1.0,
            burst_count=1,
            mean_size_bytes=128.0,
        )

        self.assertEqual(features.flow_key.dst_port, 443)
        self.assertEqual(features.mean_size_bytes, 128.0)


def _event(timestamp: datetime, size_bytes: int) -> TrafficEvent:
    return TrafficEvent(
        timestamp=timestamp,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="tcp",
        size_bytes=size_bytes,
        label="beacon",
        scenario_name="fixed",
    )


if __name__ == "__main__":
    unittest.main()
