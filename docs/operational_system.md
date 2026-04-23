# Operational Batch System

This branch starts the operational command-line system around a stable batch contract: one input,
ranked beaconing alerts, machine-readable outputs, and a readable report.

## v1 Input Contract

The canonical input is a normalized CSV. Zeek `conn.log` and NetFlow/IPFIX CSV are adapted into that
schema for scoring. CTU `.binetflow` stays in the research/demo path.

Required normalized columns:

| Column | Meaning |
| --- | --- |
| `timestamp` | ISO-8601 event timestamp. |
| `src_ip` | Source IP address. |
| `direction` | Direction label used for grouping. |
| `dst_ip` | Destination IP address. |
| `dst_port` | Destination port. |
| `protocol` | `tcp` or `udp`. |
| `total_bytes` | Total bytes for the event. |

Optional columns:

| Column | Meaning |
| --- | --- |
| `src_port` | Captured for analyst context, not used in the default grouping key. |
| `duration_seconds` | Event or connection duration. |
| `total_packets` | Total packets for the event. |
| `label` | Training label: `benign`, `beacon`, or `unknown`. Required only for `train-model`. |

Default grouping key:

```text
src_ip + dst_ip + dst_port + protocol + direction
```

## Commands

Validate:

```powershell
beacon-ops validate --input path/to/normalized.csv
```

Score normalized CSV:

```powershell
beacon-ops score --input path/to/normalized.csv --input-format normalized-csv --output-dir results/operational/run_001
```

Score Zeek `conn.log`:

```powershell
beacon-ops score --input path/to/conn.log --input-format zeek-conn --output-dir results/operational/zeek_run_001
```

Score NetFlow/IPFIX-style CSV:

```powershell
beacon-ops score --input path/to/netflow.csv --input-format netflow-ipfix-csv --output-dir results/operational/netflow_run_001
```

Score a checked-in fixture:

```powershell
beacon-ops score --input data/operational/fixtures/netflow_common_aliases.csv --input-format netflow-ipfix-csv --output-dir results/operational/example_netflow_fixture
```

The NetFlow/IPFIX adapter accepts common CSV aliases for:

| Normalized field | Common aliases |
| --- | --- |
| `timestamp` | `first_switched`, `flowStartSeconds`, `flowStartMilliseconds`, `start_time` |
| `src_ip` | `srcaddr`, `sourceIPv4Address`, `sourceIPv6Address`, `sourceAddress` |
| `src_port` | `srcport`, `sourceTransportPort` |
| `dst_ip` | `dstaddr`, `destinationIPv4Address`, `destinationIPv6Address`, `destinationAddress` |
| `dst_port` | `dstport`, `destinationTransportPort` |
| `protocol` | `proto`, `protocolIdentifier`, `transportProtocol`; supports `6`/`tcp` and `17`/`udp` |
| `total_bytes` | `bytes`, `octets`, `octetDeltaCount`, `octetTotalCount` |
| `total_packets` | `pkts`, `packetDeltaCount`, `packetTotalCount` |
| `duration_seconds` | `duration`, `dur`, `durationSecs` |

Train a Random Forest model:

```powershell
beacon-ops train-model --train path/to/labelled_train.csv --output-dir models/operational/rf_v1
```

`train-model` runs grouped validation with StratifiedGroupKFold when enough labelled groups are
available. Group IDs use the operational grouping key, so related rows from the same candidate flow
do not leak across train and validation folds. The requested fold count can be changed with
`--validation-folds`.

Export synthetic traffic into the same labelled normalized contract:

```powershell
beacon-ops export-synthetic --output data/operational/synthetic_train.csv --seed 7
```

The synthetic exporter is a bootstrap/demo source. It does not create a separate training path:
synthetic data is generated, normalized, and then passed through `train-model` like any other labelled
CSV.

Score with that saved artifact:

```powershell
beacon-ops score --input path/to/normalized.csv --input-format normalized-csv --model-artifact models/operational/rf_v1 --output-dir results/operational/run_002
```

Threshold profiles:

| Profile | Selection goal |
| --- | --- |
| `conservative` | Minimize false positives first, then prefer better precision/F1. |
| `balanced` | Maximize grouped-validation F1. |
| `sensitive` | Maximize recall first, then prefer better F1. |

Profiles are selected from out-of-fold grouped validation scores during `train-model`, recorded in
the artifact metadata, and applied at score time with `--profile`. The estimator is not retrained
when switching profiles.

## Default Outputs

Every score run writes:

| Artifact | Purpose |
| --- | --- |
| `alerts.csv` | Ranked alert rows above the conservative threshold. |
| `scored_flows.csv` | Every scored flow with rule scores and trigger metadata. |
| `run_summary.json` | Machine-readable run metadata. |
| `report.md` | Short human-readable run report. |

`run_summary.json` is the score-run manifest. It records the output roles, score semantics,
ingestion counts, skipped-row reasons, grouping policy, runtime environment, and loaded-model
metadata.

## Interpret Scores

- `rule_score` is the interpretable baseline score before thresholding.
- `rf_score` is an uncalibrated Random Forest score. Use it for ranking and thresholding, not as a direct probability.
- `hybrid_score` is the normalized ranking score that combines rules and RF signals.
- `confidence` is a threshold-relative display heuristic for alert severity, not a calibrated probability.
- Model artifacts store grouped-validation metrics, Brier score, and reliability-bin summaries from out-of-fold predictions.

## Known Ingestion Limits

- Only `tcp` and `udp` are supported in the operational path. Unsupported protocols are skipped and recorded in the score-run manifest.
- Zeek ingestion expects a `conn.log` with a `#fields` header and standard connection columns.
- NetFlow/IPFIX CSV ingestion is alias-based. It covers common exporter names and IPFIX Information Element names, but not every vendor-specific export.
- Header-only inputs fail fast. Missing required values and malformed numeric fields fail fast. Optional missing fields stay empty.
- CTU `.binetflow` remains outside the operational training contract.

## Detector Roadmap

The first operational slice is rules-first so ingestion, grouping, validation, and outputs stay
stable. The Random Forest path is artifact-based: `train-model` writes a reusable model directory
with grouped validation metrics, and `score` loads that artifact instead of retraining.
The model artifact directory includes `artifact_manifest.json`, feature names, label mapping,
training-source references, validation metrics, calibration diagnostics, threshold profiles,
dependency versions, and a pickle trust warning.

Next implementation steps:

1. Add an optional calibrated artifact path only if stronger real validation data justifies it.
2. Expand exporter-specific fixture coverage and parity testing before adding more ingestion breadth.
3. Keep LOF and statistical methods as diagnostics, not the main operational detector.
