# Operational Batch System

This branch starts the operational command-line system around a stable v1 contract: one batch input,
ranked beaconing alerts, machine-readable outputs, and a readable report.

## v1 Input Contract

The canonical input is a normalized CSV. Zeek `conn.log` is adapted into that schema first; NetFlow
and IPFIX CSV adapters come next. CTU `.binetflow` stays in the research/demo path.

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

Train a Random Forest model:

```powershell
beacon-ops train-model --train path/to/labelled_train.csv --output-dir models/operational/rf_v1
```

Score with that saved artifact:

```powershell
beacon-ops score --input path/to/normalized.csv --input-format normalized-csv --model-artifact models/operational/rf_v1 --output-dir results/operational/run_002
```

## Default Outputs

Every score run writes:

| Artifact | Purpose |
| --- | --- |
| `alerts.csv` | Ranked alert rows above the conservative threshold. |
| `scored_flows.csv` | Every scored flow with rule scores and trigger metadata. |
| `run_summary.json` | Machine-readable run metadata. |
| `report.md` | Short human-readable run report. |

## Detector Roadmap

The first operational slice is rules-first so ingestion, grouping, validation, and outputs stay
stable. The Random Forest path is artifact-based: `train-model` writes a reusable model directory,
and `score` loads that artifact instead of retraining.

Next implementation steps:

1. Add grouped validation metrics with non-overlapping groups.
2. Add a synthetic-to-normalized export helper for demo/bootstrap models.
3. Add NetFlow/IPFIX CSV ingestion.
4. Add balanced and sensitive alert profiles.
5. Keep LOF and statistical methods as diagnostics, not the main operational detector.
