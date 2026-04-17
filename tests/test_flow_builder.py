from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    GenerationScenario,
    SyntheticTrafficConfig,
    TrafficEvent,
    generate_combined_synthetic_dataset,
    save_events_to_csv,
)
from beacon_detector.flows import FlowKey, build_flows, load_flows_from_csv


class TestFlowBuilder(unittest.TestCase):
    def test_groups_events_by_flow_key(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            _event(start, "10.0.0.1", "203.0.113.1", 443, "tcp"),
            _event(start, "10.0.0.1", "203.0.113.1", 443, "tcp"),
            _event(start, "10.0.0.2", "203.0.113.1", 443, "tcp"),
        ]

        flows = build_flows(events)

        self.assertEqual(len(flows), 2)
        self.assertEqual(sorted(flow.event_count for flow in flows), [1, 2])

    def test_orders_events_within_each_flow(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        later = _event(start + timedelta(seconds=30), "10.0.0.1", "203.0.113.1", 443, "tcp")
        earlier = _event(start, "10.0.0.1", "203.0.113.1", 443, "tcp")

        flow = build_flows([later, earlier])[0]

        self.assertEqual(flow.events[0].timestamp, start)
        self.assertEqual(flow.events[1].timestamp, start + timedelta(seconds=30))

    def test_expected_flow_count_for_simple_synthetic_example(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            _event(start, "10.0.0.1", "203.0.113.1", 443, "tcp"),
            _event(start, "10.0.0.1", "203.0.113.2", 443, "tcp"),
            _event(start, "10.0.0.1", "203.0.113.2", 80, "tcp"),
            _event(start, "10.0.0.1", "203.0.113.2", 80, "udp"),
        ]

        self.assertEqual(len(build_flows(events)), 4)

    def test_mixed_labels_and_scenarios_are_preserved_on_flow(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            _event(start, "10.0.0.1", "203.0.113.1", 443, "tcp", label="benign", scenario_name="normal"),
            _event(start + timedelta(seconds=5), "10.0.0.1", "203.0.113.1", 443, "tcp", label="beacon", scenario_name="fixed_periodic"),
        ]

        flow = build_flows(events)[0]

        self.assertEqual(flow.label, "beacon")
        self.assertEqual(flow.scenario_names, ("fixed_periodic", "normal"))

    def test_can_load_synthetic_csv_and_convert_to_flows(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=12,
            normal_event_count=8,
            beacon_event_count=4,
        )
        events = generate_combined_synthetic_dataset(config)
        csv_path = Path("tests/.tmp/flow_builder_events.csv")
        try:
            save_events_to_csv(events, csv_path)
            flows = load_flows_from_csv(csv_path)
        finally:
            if csv_path.exists():
                csv_path.unlink()

        self.assertGreater(len(flows), 1)
        self.assertTrue(all(flow.event_count >= 1 for flow in flows))

    def test_scenario_offsets_are_applied(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        config = SyntheticTrafficConfig(
            start_time=start,
            seed=4,
            normal_event_count=5,
            beacon_event_count=3,
            normal_start_offset_seconds=11.0,
            fixed_start_offset_seconds=0.0,
            jittered_start_offset_seconds=23.0,
            bursty_start_offset_seconds=47.0,
            time_size_jittered_start_offset_seconds=89.0,
        )

        events = generate_combined_synthetic_dataset(config)
        first_by_scenario = {
            scenario.value: min(
                event.timestamp for event in events if event.scenario_name == scenario.value
            )
            for scenario in (
                GenerationScenario.FIXED,
                GenerationScenario.JITTERED,
                GenerationScenario.BURSTY,
                GenerationScenario.TIME_SIZE_JITTERED,
            )
        }

        normal_first = min(
            event.timestamp for event in events if event.scenario_name.startswith("normal_")
        )
        self.assertGreaterEqual(normal_first, start + timedelta(seconds=11))
        self.assertEqual(first_by_scenario["fixed_periodic"], start)
        self.assertEqual(first_by_scenario["jittered"], start + timedelta(seconds=23))
        self.assertEqual(first_by_scenario["bursty"], start + timedelta(seconds=47))
        self.assertEqual(first_by_scenario["time_size_jittered"], start + timedelta(seconds=89))
        self.assertEqual(len(set(first_by_scenario.values())), len(first_by_scenario))

    def test_synthetic_beacon_scenarios_have_distinct_flow_keys(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=9,
            normal_event_count=10,
            beacon_event_count=5,
        )
        flows = build_flows(generate_combined_synthetic_dataset(config))
        beacon_flow_keys_by_scenario = {}

        for scenario in (
            GenerationScenario.FIXED,
            GenerationScenario.JITTERED,
            GenerationScenario.BURSTY,
            GenerationScenario.TIME_SIZE_JITTERED,
        ):
            matching_flows = [
                flow
                for flow in flows
                if flow.label == "beacon" and flow.scenario_names == (scenario.value,)
            ]
            self.assertEqual(len(matching_flows), 1)
            beacon_flow_keys_by_scenario[scenario.value] = matching_flows[0].flow_key

        self.assertEqual(
            len(set(beacon_flow_keys_by_scenario.values())),
            len(beacon_flow_keys_by_scenario),
        )


def _event(
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    label: str = "benign",
    scenario_name: str = "normal",
) -> TrafficEvent:
    return TrafficEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,  # type: ignore[arg-type]
        size_bytes=100,
        label=label,  # type: ignore[arg-type]
        scenario_name=scenario_name,
    )


if __name__ == "__main__":
    unittest.main()
