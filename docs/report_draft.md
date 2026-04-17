# Beaconing Detection From Flow-Level Behaviour

This report summarizes a Python research project on detecting command-and-control beaconing from
flow-level behaviour. The project is intentionally comparative: it evaluates several detector
families, hardens the benchmark over time, and preserves failure modes instead of hiding them.

## Introduction

Command-and-control beaconing is a repeated communication pattern often used by compromised hosts.
Simple beaconing may be periodic, but attackers can add timing jitter, size variation, and burst
patterns to make regularity harder to detect. This project asks how far flow-level behavioural
features can go when the detector does not inspect payloads.

The project should not be read as a production monitoring system. Its value is the research process:
controlled synthetic generation, common feature extraction, detector comparison, stress testing,
public-data transfer checks, and honest limitation analysis.

## Research Question

How effectively can flow-level statistical and machine learning methods detect beaconing traffic
when attackers introduce timing jitter, size variation, and burst-based communication patterns?

Supporting questions:

- Which detector families work best on controlled synthetic beaconing?
- Which benign repeated behaviours create false positives?
- How much flow history is needed before evasive beaconing becomes detectable?
- Do synthetic-trained assumptions transfer to CTU-13 public flow data?

## Pipeline And Methodology

The project pipeline is:

```text
synthetic/public data -> flows -> behavioural features -> detectors -> evaluations -> exports
```

Synthetic events are grouped into flows using:

```text
src_ip, dst_ip, dst_port, protocol
```

Feature extraction is central. The same flow-level feature representation feeds rules, statistical
scoring, anomaly detection, and supervised ML. Features cover timing, size, rate, burst structure,
interval consistency, and low-sample similarity. Short flows are handled explicitly because the
minimum-evidence question became one of the main research findings.

## Synthetic Benchmark

The malicious synthetic scenarios are:

- `fixed_periodic`: stable interval and stable size.
- `jittered`: timing varies around a mean interval.
- `bursty`: clustered communication separated by sleeps.
- `time_size_jittered`: both timing and size vary; this is the hardest malicious family.

Benign traffic is split into explicit profiles rather than one generic normal class:

- `normal_software_update`
- `normal_telemetry`
- `normal_cloud_sync`
- `normal_api_polling`
- `normal_bursty_session`
- `normal_keepalive`

This matters because false positives are not all the same. A detector that over-flags keepalives is
failing differently from one that over-flags bursty benign sessions.

## Detector Progression

The detector progression is deliberately simple and interpretable before becoming more flexible:

1. Frozen rule baseline
2. Statistical z-score baseline
3. Isolation Forest and Local Outlier Factor anomaly baselines
4. Logistic Regression and Random Forest supervised baselines

The rule baseline remains the strongest interpretable reference. The statistical baseline is useful
for transparency but weak under multimodal benign traffic. LOF is the most meaningful anomaly
baseline, but it is not strongest overall. Random Forest is strongest on the controlled synthetic
benchmark, while still failing in the hardest low-evidence evasive regime.

## Evaluation Design

The project does not rely on one easy synthetic run. It includes:

- hardened multi-seed synthetic evaluation
- explicit adversarial benign profiles
- held-out validation
- shortcut/overlap stress testing
- RF signal studies
- minimum-evidence analysis
- CTU-13 direct transfer
- CTU-native feature adaptation
- within-CTU supervised validation

Metrics include precision, recall, F1, false-positive rate, confusion matrix counts, per-scenario
rates, and per-profile false-flag rates.

## Results

On the controlled synthetic benchmark, Random Forest is the strongest overall detector. The rule
baseline is also strong and remains important because it gives an interpretable reference point. The
statistical baseline and anomaly baselines provide useful comparison points, but neither becomes the
lead model.

Shortcut stress and held-out validation are where the story becomes more interesting. They show that
strong synthetic benchmark performance does not mean the detector has solved beaconing generally.
The hardest failure remains low-event, high-jitter, size-overlapping `time_size_jittered` traffic.
In that regime, Random Forest can confidently score malicious flows as benign.

The curated final results are under:

```text
results/tables/final_story/
results/figures/final_story/
```

The older `report_ready/` and experiment-specific folders are retained as supporting evidence.

## Minimum-Evidence Finding

Minimum evidence is the core research result. Easy regimes such as fixed periodic, jittered, and
bursty beaconing can be detected with little flow history. Evasive `time_size_jittered` regimes need
substantially more observations before the current aggregate feature representation becomes useful.

The key interpretation is not simply that one threshold was too strict. At low event counts, there
may not be enough behavioural evidence for aggregate flow features to separate evasive beaconing
from benign repeated communication. That makes minimum evidence a modelling constraint, not just a
configuration issue.

## CTU-13 Public-Data Validation

The CTU story is deliberately split into three stages:

```text
Synthetic direct transfer to CTU
CTU-native unsupervised evaluation
Within-CTU supervised evaluation
```

Synthetic direct transfer tests whether synthetic-designed or synthetic-trained detectors carry over
to adapted CTU rows. It exposes domain shift: synthetic-trained RF finds many botnet-labelled flows,
but false positives are high.

CTU-native unsupervised evaluation uses `.binetflow` fields directly rather than forcing CTU rows
through synthetic-style flow features. This is more honest, but still not a full solution.

Within-CTU supervised evaluation trains Logistic Regression and Random Forest on CTU-native fields
with scenario-aware splits. It tests whether the native representation has discriminative power when
trained appropriately on public data. Results are mixed: CTU-native RF reduces false positives but
misses many botnet flows, while CTU-native Logistic Regression recalls more but overfires.

This is a stronger public-data story than pretending synthetic transfer works perfectly. It is also
more honest: CTU-13 validation shows real schema and domain-shift limits.

## Lightweight Detector Interface

The project includes a small local CTU scorer:

```powershell
python -m beacon_detector.cli.score --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --input-format ctu13-binetflow --detector ctu-native-random-forest --train-scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --train-scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/scored/ctu13_scenario_7
```

It writes a scored CSV, summary JSON, and markdown summary. This makes the pipeline runnable and
inspectable, but it is not a live detector, dashboard, or SOC platform.

## Limitations

- Synthetic traffic is controlled research data, not real network traffic.
- Flow-level aggregate features ignore payloads, host context, DNS/TLS metadata, and process context.
- Supervised models may learn generator-specific shortcuts.
- Low-event evasive `time_size_jittered` remains difficult.
- CTU-13 labels include ambiguous Background traffic, handled separately as sensitivity analysis.
- CTU-native modelling improves honesty of the public-data path but does not prove deployment
  readiness.

## Conclusion

Synthetic benchmark results are strong, especially for Random Forest, but the most important research finding is the minimum-evidence result: easy beaconing regimes can be detected with little flow history, while evasive low-event, high-jitter, size-overlapping regimes require substantially more evidence. CTU-13 validation exposes schema and domain shift that synthetic results alone would hide. CTU-native modelling is a more honest public-data path than forcing CTU bidirectional rows through synthetic-style features, but it is still not deployment proof. This project is a comparative flow-level detection study, not a production SOC detector.
