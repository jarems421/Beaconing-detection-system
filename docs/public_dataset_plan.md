# Public Dataset Adapter Plan

This document describes public-data support. The first implemented adapter is a narrow CTU-13
bidirectional `.binetflow` adapter; broader public dataset support is still future work.

## Goal

Validate the flow-level beaconing pipeline beyond synthetic data while preserving the same core path:

```text
raw/public data -> TrafficEvent rows -> Flow objects -> FlowFeatures -> detectors/evaluation
```

## Candidate Dataset Families

Datasets to investigate:

```text
CTU-13 / Stratosphere malware captures
Stratosphere IPS Malware Capture Facility traces
CIC-IDS2017 or CSE-CIC-IDS2018
UGR'16
UNSW-NB15
```

These are candidates, not confirmed drop-in inputs. Each one needs licensing, schema, label quality,
and timestamp/flow compatibility checked before use.

## Required Field Mapping

The current event model expects at least:

```text
timestamp
src_ip
dst_ip
dst_port
protocol
size_bytes
label
scenario_name
```

Likely public-data mappings:

```text
timestamp          -> packet timestamp, flow start time, or connection timestamp
src_ip / dst_ip    -> source and destination address fields
dst_port           -> destination port field
protocol           -> protocol field, normalized to values such as TCP/UDP
size_bytes         -> packet length, bytes transferred, or direction-specific byte count
label              -> benign vs malicious, when available
scenario_name      -> dataset family, malware family, capture name, or benign profile proxy
```

If a dataset is already flow-based rather than event-based, the adapter should either:

1. map its rows into `FlowFeatures` directly only when the fields are compatible, or
2. map available timestamps/events into `TrafficEvent` rows and reuse the current flow builder.

The second path is preferable when possible because it keeps feature extraction centralized.

## Transferable Features

Likely transferable:

```text
event_count
flow_duration_seconds
inter-arrival statistics
periodicity and interval-consistency features
burst-shape features
size variation features
destination/flow-key consistency
```

These depend mostly on timing, counts, and sizes, so they should transfer if the dataset has enough
event-level detail.

## Features That May Not Transfer Cleanly

Potential issues:

```text
size_bytes may mean packet length in one dataset and connection bytes in another
timestamp resolution may be too coarse for interval features
directionality may be missing or pre-aggregated
labels may be host-level, capture-level, or malware-family-level rather than flow-level
benign traffic may not contain realistic repeated background services
```

The adapter should record these limitations in metadata so later evaluation does not treat all
datasets as equally comparable.

## Adapter Design

Recommended implementation path:

1. Add dataset-specific parsers under `src/beacon_detector/parsing/`.
2. Normalize rows into the existing `TrafficEvent` model where possible.
3. Reuse `build_flows()` and feature extraction unchanged.
4. Add dataset metadata with source name, label assumptions, timestamp units, and size semantics.
5. Keep public-data evaluations separate from synthetic benchmark results.

## Implemented First Adapter: CTU-13

The CTU-13 adapter supports bidirectional `.binetflow` files from the
`detailed-bidirectional-flow-labels` folders.

Current mapping:

```text
CTU StartTime -> TrafficEvent.timestamp
CTU SrcAddr   -> TrafficEvent.src_ip
CTU DstAddr   -> TrafficEvent.dst_ip
CTU Dport     -> TrafficEvent.dst_port
CTU Proto     -> TrafficEvent.protocol, limited to tcp/udp
CTU TotBytes  -> TrafficEvent.size_bytes
CTU Label     -> TrafficEvent.label using the explicit CTU label policy
```

Each CTU bidirectional flow row is treated as a connection-level event. The project then groups
those events by the existing flow key and extracts behavioural timing/size features across repeated
CTU flow records.

Default label policy:

```text
From-Botnet -> beacon
From-Normal -> benign
Background -> skipped
To-Botnet -> skipped
To-Normal -> skipped
```

This is intentionally conservative. CTU-13 documentation warns that `To-Botnet` and `To-Normal`
flows should not be considered malicious/benign by default, and background traffic is not cleanly
verified normal traffic.

Current CTU-13 evaluation command:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario-name ctu13_scenario_7 --output-dir results/tables/ctu13
```

Current multi-scenario evaluation command:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_multi
```

The multi-scenario output keeps the conservative label policy as the primary result and writes a
separate background-as-benign sensitivity analysis.

## Validation Checks

Each public adapter should verify:

```text
required columns exist
timestamps parse correctly
protocol and ports are normalized
labels are mapped explicitly
flow keys are not accidentally collapsed
flow event counts are plausible
feature extraction handles the imported data without special detector logic
```

## Known Limitations

Public dataset support will not automatically prove real-world deployability. The current project is
still a flow-level behavioural detector with no payload inspection, no live network integration, and
no guarantee that public labels map cleanly to flow-level beaconing behaviour.
