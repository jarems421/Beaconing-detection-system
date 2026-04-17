from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_detector.data import (
    CsvTrafficDataLoader,
    GenerationScenario,
    NormalTrafficProfile,
    ShortcutOverlapLevel,
    SyntheticTrafficConfig,
    generate_combined_synthetic_dataset,
    generate_time_size_jittered_beaconing,
    generate_synthetic_events,
    save_events_to_csv,
)
from beacon_detector.data.types import PacketEvent


class TestDataStage1(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SyntheticTrafficConfig(
            duration_seconds=600,
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=42,
            normal_event_count=40,
            beacon_event_count=12,
        )

    def test_generates_events_for_all_scenarios(self) -> None:
        for scenario in GenerationScenario:
            events = generate_synthetic_events(self.config, scenario)
            self.assertGreater(len(events), 0)
            labels = Counter(event.label for event in events)
            self.assertGreater(labels["benign"], 0)
            if scenario is not GenerationScenario.NORMAL:
                self.assertGreater(labels["beacon"], 0)

    def test_fixed_vs_jittered_interval_variation(self) -> None:
        fixed = generate_synthetic_events(self.config, GenerationScenario.FIXED)
        jittered = generate_synthetic_events(self.config, GenerationScenario.JITTERED)

        fixed_beacon = [event for event in fixed if event.label == "beacon"]
        jitter_beacon = [event for event in jittered if event.label == "beacon"]

        fixed_deltas = _interval_seconds(fixed_beacon)
        jitter_deltas = _interval_seconds(jitter_beacon)

        self.assertEqual(len(set(fixed_deltas)), 1)
        self.assertGreater(len(set(jitter_deltas)), 1)

    def test_csv_round_trip(self) -> None:
        events = generate_synthetic_events(self.config, GenerationScenario.BURSTY)
        tmp_root = Path("tests/.tmp")
        tmp_root.mkdir(parents=True, exist_ok=True)
        csv_path = tmp_root / "events_round_trip.csv"
        try:
            save_events_to_csv(events, csv_path)
            loaded = CsvTrafficDataLoader().load(csv_path)
        finally:
            if csv_path.exists():
                csv_path.unlink()
        self.assertEqual(events, loaded)

    def test_combined_dataset_has_all_scenario_names(self) -> None:
        events = generate_combined_synthetic_dataset(self.config)
        scenario_names = {event.scenario_name for event in events}

        self.assertTrue(any(name.startswith("normal_") for name in scenario_names))
        self.assertIn("fixed_periodic", scenario_names)
        self.assertIn("jittered", scenario_names)
        self.assertIn("bursty", scenario_names)
        self.assertIn("time_size_jittered", scenario_names)

    def test_named_benign_profiles_are_generated(self) -> None:
        config = SyntheticTrafficConfig(
            duration_seconds=1200,
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=43,
            normal_event_count=36,
            normal_flow_count=len(NormalTrafficProfile),
        )

        events = generate_synthetic_events(config, GenerationScenario.NORMAL)
        scenario_names = {event.scenario_name for event in events}

        for profile in NormalTrafficProfile:
            self.assertIn(profile.value, scenario_names)

    def test_default_normal_generation_does_not_spill_into_singletons(self) -> None:
        events = generate_synthetic_events(
            SyntheticTrafficConfig(
                start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                seed=45,
            ),
            GenerationScenario.NORMAL,
        )
        counts_by_flow_key: dict[tuple[str, str, int, str], int] = {}
        for event in events:
            key = (event.src_ip, event.dst_ip, event.dst_port, event.protocol)
            counts_by_flow_key[key] = counts_by_flow_key.get(key, 0) + 1

        self.assertNotIn(1, counts_by_flow_key.values())
        self.assertNotIn(2, counts_by_flow_key.values())

    def test_normal_size_sampling_handles_narrow_config_ranges(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=46,
            normal_event_count=24,
            normal_flow_count=6,
            normal_size_min_bytes=80,
            normal_size_max_bytes=100,
        )

        events = generate_synthetic_events(config, GenerationScenario.NORMAL)

        self.assertTrue(all(80 <= event.size_bytes <= 100 for event in events))

    def test_shortcut_overlap_defaults_to_existing_low_difficulty(self) -> None:
        config = SyntheticTrafficConfig()

        self.assertEqual(config.shortcut_overlap_level, ShortcutOverlapLevel.LOW)

    def test_shortcut_overlap_level_is_explicitly_configurable(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=47,
            normal_event_count=30,
            normal_flow_count=6,
            normal_events_per_flow_min=4,
            normal_events_per_flow_max=6,
            shortcut_overlap_level=ShortcutOverlapLevel.HIGH,
        )

        events = generate_synthetic_events(config, GenerationScenario.NORMAL)

        self.assertGreater(len(events), 0)
        self.assertTrue(all(event.label == "benign" for event in events))
        self.assertTrue(any(event.scenario_name == "normal_keepalive" for event in events))

    def test_time_size_jittered_can_use_low_event_stress_count(self) -> None:
        config = SyntheticTrafficConfig(
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            seed=48,
            beacon_event_count=12,
            time_size_jittered_event_count=5,
            time_size_jittered_jitter_fraction=0.95,
            time_size_jittered_size_jitter_fraction=0.95,
        )

        events = generate_time_size_jittered_beaconing(config)

        self.assertEqual(len(events), 5)
        self.assertTrue(all(event.scenario_name == "time_size_jittered" for event in events))


def _interval_seconds(events: list[PacketEvent]) -> list[int]:
    intervals: list[int] = []
    for idx in range(1, len(events)):
        delta = events[idx].timestamp - events[idx - 1].timestamp
        intervals.append(int(round(delta.total_seconds())))
    return intervals


if __name__ == "__main__":
    unittest.main()
