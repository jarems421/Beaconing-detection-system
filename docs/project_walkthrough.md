# Project Walkthrough

This walkthrough gives a short, reader-facing tour of the project. It is not a dashboard, live
monitoring interface, or production SOC workflow. It is a compact guide to the evidence,
main findings, and runnable entrypoints.

## 1. Research Question

The project asks:

```text
How effectively can flow-level statistical and machine learning methods detect beaconing traffic
when attackers introduce timing jitter, size variation, and burst-based communication patterns?
```

The detection unit is a flow rather than a packet. The project focuses on behavioural metadata such
as timing, size, burst structure, repetition, and flow duration instead of payload signatures.

## 2. Pipeline

The implemented pipeline is:

```text
synthetic/public data -> flows -> behavioural features -> detectors -> evaluations -> exports
```

The same broad feature pipeline supports rules, statistical scoring, anomaly detection, and
supervised ML. That shared representation makes detector comparisons easier to interpret.

## 3. Core Finding: Minimum Evidence

The central research result is the minimum-evidence finding.

Headline figure:

```text
results/figures/final_story/02_minimum_evidence_core_result.png
```

Main takeaway:

```text
Easy beaconing regimes can be detected with little flow history, but evasive low-event,
high-jitter, size-overlapping traffic requires substantially more observations before the current
flow-level features become reliable.
```

This matters because the hardest missed flows are not merely near a bad threshold. In the hardest
time+size jittered regime, the available flow history is too thin for aggregate features to separate
malicious and benign behaviour reliably.

## 4. Synthetic Benchmark Result

The controlled synthetic benchmark tests fixed periodic, jittered, bursty, and time+size jittered
beaconing alongside harder benign profiles.

Headline figure:

```text
results/figures/final_story/01_synthetic_detector_comparison.png
```

Main takeaway:

```text
Random Forest is the strongest overall detector on the controlled synthetic benchmark. The frozen
rule baseline remains the main interpretable reference.
```

## 5. CTU-13 Public-Data Reality Check

The CTU-13 validation is deliberately split into three stages:

```text
Synthetic direct transfer to CTU
CTU-native unsupervised evaluation
Within-CTU supervised evaluation
```

Headline figure:

```text
results/figures/final_story/03_ctu_three_stage_comparison.png
```

Main takeaway:

```text
Synthetic direct transfer exposes schema and domain shift. CTU-native features are better aligned
with the public flow schema, but the CTU results are still not deployment proof.
```

The three-stage split avoids blurring synthetic-trained transfer results with CTU-native modelling,
and it keeps ambiguous public-data limitations visible.

## 6. Runnable Local Interface

The project includes a lightweight local scorer for CTU-13 `.binetflow` files. It trains from
explicit CTU training scenario files and writes scored outputs for a supported input file.

Help command:

```powershell
python -m beacon_detector.cli.score --help
```

Example command shape:

```powershell
python -m beacon_detector.cli.score --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --input-format ctu13-binetflow --detector ctu-native-random-forest --train-scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --train-scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/scored/ctu13_scenario_7
```

The scorer is intentionally local and research-oriented. It is not a dashboard, live packet monitor,
or production alerting system.

## 7. Suggested Short Walkthrough Path

A concise project tour can follow this sequence:

1. Research question.
2. Minimum-evidence figure.
3. Synthetic detector comparison.
4. CTU three-stage comparison.
5. `python -m beacon_detector.cli.score --help`.
6. Final conclusion.

Recommended length for a short recording: two to three minutes.

## 8. Final Conclusion

Synthetic benchmark results are strong, especially for Random Forest, but the most important
research finding is the minimum-evidence result: easy beaconing regimes can be detected with little
flow history, while evasive low-event, high-jitter, size-overlapping regimes require substantially
more evidence. CTU-13 validation exposes schema and domain shift that synthetic results alone would
hide. CTU-native modelling is a better aligned public-data path than forcing CTU bidirectional rows
through synthetic-style features, but it is still not deployment proof. This project is a
comparative flow-level detection study, not a production SOC detector.
