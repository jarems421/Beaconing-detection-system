# Beaconing Detection System

Flow-level behavioural detection of command-and-control beaconing under timing jitter, size variation,
burst traffic, hard benign profiles, and CTU-13 public-data domain shift.

**Headline result:** strong controlled synthetic performance does not automatically transfer to
public flow data. Minimum evidence requirements and CTU-13 schema/domain shift are the key limits.

## At A Glance

| Question | Short answer |
| --- | --- |
| Task | Detect C2 beaconing from flow-level behaviour, not payload signatures. |
| Approach | Compare interpretable rules, statistical scoring, anomaly detection, and supervised ML on synthetic and CTU-13 traffic. |
| Best synthetic model | Random Forest is strongest on the controlled synthetic benchmark. |
| Core finding | Minimum evidence matters: evasive low-event, high-jitter, size-overlapping flows need substantially more history. |
| CTU takeaway | Public CTU-13 validation exposes schema/domain shift that synthetic results alone would hide. |
| Final claim | This is a comparative flow-level detection study, not a production SOC detector. |

## Motivation

Beaconing can look periodic, but real benign traffic and evasive attacker behaviour make simple
periodicity checks unreliable. Attackers can add timing jitter, vary payload sizes, communicate in
bursts, or keep flows short enough that there is not much evidence to learn from. This project studies
where flow-level behavioural detection works, where it breaks, and how results change when the same
ideas are tested against CTU-13 public flow data.

## Key Findings

- Flow-level behavioural features can detect fixed, jittered, and bursty synthetic beaconing well.
- Hard benign repeated traffic and shortcut/overlap stress expose false positives and brittle assumptions.
- The strongest research result is a minimum-evidence finding: evasive beaconing needs enough flow
  history before aggregate features become reliable.

## Research Question

How effectively can flow-level statistical and machine learning methods detect beaconing traffic when
attackers introduce timing jitter, size variation, and burst-based communication patterns?

## Architecture

```mermaid
flowchart LR
    A[Synthetic generator / CTU-13 public data] --> B[Flow construction]
    B --> C[Behavioural feature extraction]
    C --> D[Detector families]
    D --> E[Evaluation tracks]
    E --> F[Report-ready tables and figures]

    D --> D1[Rules]
    D --> D2[Statistical scoring]
    D --> D3[Anomaly detection]
    D --> D4[Supervised ML]

    E --> E1[Synthetic hardened grid]
    E --> E2[Stress and minimum-evidence studies]
    E --> E3[CTU-13 validation]
```

## Key Results

The strongest project finding is the minimum-evidence result: easy beaconing regimes can be detected
with little flow history, while evasive time-and-size jittered traffic requires more evidence before
the current flow-level features become reliable.

![Minimum-evidence core result](results/figures/final_story/02_minimum_evidence_core_result.png)

On the controlled synthetic benchmark, Random Forest is the strongest overall model, while the frozen
rule baseline remains the main interpretable reference.

![Synthetic detector comparison](results/figures/final_story/01_synthetic_detector_comparison.png)

The public-data validation result is more cautious. CTU-13 exposes schema and domain shift:
synthetic-transfer RF can detect many botnet-labelled flows but false-positives heavily, while
CTU-native approaches are better aligned with the public data schema but still limited.

![CTU three-stage comparison](results/figures/final_story/03_ctu_three_stage_comparison.png)

## Detector Tradeoffs

| Detector family | Role in project | Main strength | Main limitation |
| --- | --- | --- | --- |
| Frozen rules | Interpretable reference baseline | Easy to inspect and explain | Brittle under evasive timing and benign repeated traffic |
| Statistical z-score | Transparent statistical baseline | Simple benign-reference comparison | Weak under multimodal benign behaviour |
| Isolation Forest / LOF | Anomaly baselines | Useful unsupervised comparison point | Not strongest overall; can be unstable at low evidence |
| Logistic Regression | Linear supervised baseline | Clear supervised reference | Less flexible than Random Forest |
| Random Forest | Strongest synthetic benchmark model | Best controlled synthetic performance | Lower interpretability and still weak on hardest low-evidence regimes |

## Public-Data Validation

CTU-13 evidence is deliberately split into three stages:

```text
Synthetic direct transfer to CTU
CTU-native unsupervised evaluation
Within-CTU supervised evaluation
```

This separation matters. Synthetic direct transfer exposes domain shift, CTU-native unsupervised
evaluation uses `.binetflow` fields directly, and within-CTU supervised evaluation tests whether
those native features have discriminative power under scenario-aware splits.

## Repo Guide

| Path | Purpose |
| --- | --- |
| `src/beacon_detector/` | Core package: generation/loading, flows, features, detectors, evaluation, and CLI. |
| `tests/` | Regression tests for models, features, evaluation, CTU adapters, exports, and CLI plumbing. |
| `docs/operational_system.md` | Operational batch scoring design and v1 command contract. |
| `docs/project_walkthrough.md` | Guided project walkthrough. |
| `docs/report_draft.md` | More complete technical writeup. |
| `results/figures/final_story/` | Headline figures to view first. |
| `results/tables/final_story/` | Curated summary tables for the final story. |
| `results/tables/report_ready/` | Intermediate report-ready summaries used by the final story layer. |
| `data/synthetic/sample_events.csv` | Small generated synthetic sample. |
| `data/public/README.md` | Expected CTU-13 local data layout; raw CTU files are not committed. |

## Project Walkthrough

For a compact reader-facing tour of the project, use:

```text
docs/project_walkthrough.md
```

The walkthrough connects the README figures, the minimum-evidence result, the CTU domain-shift
result, and one local scorer command. It is not a dashboard or production monitoring interface.

## Setup

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Optional lint tooling:

```powershell
python -m pip install -e ".[dev]"
```

## Quick Start

Run the tests:

```powershell
python -m unittest discover -s tests
```

Run lint checks:

```powershell
python -m ruff check .
```

Run a quick synthetic evaluation:

```powershell
python -m beacon_detector.evaluation.run --quick
```

## Operational Batch CLI

The operational v1 path scores a normalized CSV or Zeek `conn.log` as one batch and writes four
default outputs:

```text
alerts.csv
scored_flows.csv
run_summary.json
report.md
```

Canonical normalized CSV columns:

| Column | Required | Notes |
| --- | --- | --- |
| `timestamp` | Yes | ISO-8601 timestamp; naive timestamps are treated as UTC. |
| `src_ip` | Yes | Source host. |
| `direction` | Yes | Direction label used in the flow grouping key. |
| `dst_ip` | Yes | Destination host. |
| `dst_port` | Yes | Destination port. |
| `protocol` | Yes | `tcp` or `udp`. |
| `total_bytes` | Yes | Non-negative integer. |
| `src_port` | No | Captured for context, not used in default grouping. |
| `duration_seconds` | No | Non-negative numeric value. |
| `total_packets` | No | Non-negative integer. |
| `label` | Training only | `benign`, `beacon`, or `unknown`; unknown rows are skipped by training. |

Validate a normalized CSV:

```powershell
beacon-ops validate --input data/operational/sample_normalized.csv
```

Score a normalized CSV:

```powershell
beacon-ops score --input data/operational/sample_normalized.csv --input-format normalized-csv --output-dir results/operational/run_001
```

Train a Random Forest model from labelled normalized CSV rows:

```powershell
beacon-ops train-model --train data/operational/labelled_train.csv --output-dir models/operational/rf_v1
```

Score with the saved model artifact loaded at runtime:

```powershell
beacon-ops score --input data/operational/sample_normalized.csv --input-format normalized-csv --model-artifact models/operational/rf_v1 --output-dir results/operational/run_002
```

Score a Zeek `conn.log`:

```powershell
beacon-ops score --input data/zeek/conn.log --input-format zeek-conn --output-dir results/operational/zeek_run_001
```

Without `--model-artifact`, scoring uses the conservative rules path. With `--model-artifact`,
scoring loads the saved Random Forest artifact and writes hybrid rules + RF scores without retraining.

## Reproduce Key Artifacts

Regenerate report-ready and final-story artifacts from existing exports:

```powershell
python -c "from beacon_detector.evaluation.report_artifacts import build_report_artifacts; build_report_artifacts()"
```

## CTU Evaluation Commands

Run CTU direct-transfer evaluation:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_multi
```

The optional background-as-benign sensitivity path caps retained CTU Background feature rows per
scenario by default so it can complete on a local workstation; the conservative policy remains the
headline CTU direct-transfer result.

Run CTU-native feature-path comparison:

```powershell
python -m beacon_detector.evaluation.run_ctu13_native --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_native
```

Run within-CTU supervised evaluation:

```powershell
python -m beacon_detector.evaluation.run_ctu13_supervised --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_supervised
```

## Local Scorer

Run the lightweight local CTU scorer:

```powershell
python -m beacon_detector.cli.score --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --input-format ctu13-binetflow --detector ctu-native-random-forest --train-scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --train-scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/scored/ctu13_scenario_7
```

## Limitations

- Synthetic traffic is useful for controlled experiments, but it is simplified and can contain generator artifacts.
- CTU-13 introduces schema and domain shift; public-data results are deliberately reported separately.
- Flow-level aggregate features have evidence limits for evasive low-event traffic.
- The local scorer is a research interface, not a production SOC detector.

## Final Conclusion

Synthetic benchmark results are strong, especially for Random Forest, but the most important
research finding is the minimum-evidence result: easy beaconing regimes can be detected with little
flow history, while evasive low-event, high-jitter, size-overlapping regimes require substantially
more evidence. CTU-13 validation exposes schema and domain shift that synthetic results alone would
hide. CTU-native modelling is a better public-data path than forcing CTU bidirectional rows through
synthetic-style features, but it is still not deployment proof. This project is a
comparative flow-level detection study, not a production SOC detector.
