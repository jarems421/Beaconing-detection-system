# Demo Script

This is a short walkthrough script for interviews, coursework demos, or a quick screen recording. It
does not add a new app or dashboard. The goal is to explain the project clearly in about two to
three minutes.

## 30-Second Version

This project studies flow-level detection of command-and-control beaconing when attackers add timing
jitter, size variation, and burst-based communication. I built a full Python research pipeline:
synthetic/public data adapters, flow construction, behavioural features, rule/statistical/anomaly
baselines, supervised ML, stress testing, CTU-13 validation, and report-ready artifacts. The main
finding is not just that Random Forest performs well on synthetic data. The stronger result is that
minimum evidence matters: easy beaconing can be detected with little flow history, but evasive
low-event, high-jitter, size-overlapping traffic needs substantially more observations. CTU-13 then
shows that synthetic success does not automatically transfer to public data because of schema and
domain shift.

## 2-3 Minute Walkthrough

### 1. Start With The Research Question

Open `README.md` and point to the research question:

```text
How effectively can flow-level statistical and machine learning methods detect beaconing traffic
when attackers introduce timing jitter, size variation, and burst-based communication patterns?
```

Say:

```text
The project is about behavioural detection at the flow level. It deliberately avoids payload
signatures and asks how far timing, size, burst, and repetition features can go.
```

### 2. Show The Pipeline

Point to the implemented pipeline:

```text
synthetic/public data -> flows -> behavioural features -> detectors -> evaluations -> exports
```

Say:

```text
The same feature pipeline is reused across rules, statistical scoring, anomaly detection, and
supervised ML. That makes the comparisons fairer and easier to diagnose.
```

### 3. Show The Synthetic Benchmark Result

Scroll to the synthetic detector comparison figure:

```text
results/figures/final_story/01_synthetic_detector_comparison.png
```

Say:

```text
On the controlled synthetic benchmark, Random Forest is the strongest overall detector. The rule
baseline remains important because it is interpretable and gives a clear reference point.
```

### 4. Emphasize The Core Result

Show the minimum-evidence figure:

```text
results/figures/final_story/02_minimum_evidence_core_result.png
```

Say:

```text
This is the main research finding. Easy regimes become detectable with very few events, but evasive
time-and-size jittered traffic needs much more flow history. The hardest failures are not just bad
thresholds. They are minimum-evidence problems.
```

### 5. Show The Public-Data Reality Check

Show the CTU three-stage comparison:

```text
results/figures/final_story/03_ctu_three_stage_comparison.png
```

Say:

```text
CTU-13 is where the project becomes more honest. Synthetic direct transfer exposes domain shift.
CTU-native features are a better public-data path, and within-CTU supervised evaluation tests
whether those native features have discriminative power. The results are useful, but not deployment
proof.
```

Keep the three CTU labels explicit:

```text
Synthetic direct transfer to CTU
CTU-native unsupervised evaluation
Within-CTU supervised evaluation
```

### 6. Show One Runnable Command

Run a lightweight smoke command:

```powershell
python -m beacon_detector.cli.score --help
```

Say:

```text
The repo includes a local scorer for supported CTU .binetflow files. It trains from explicit CTU
training scenarios and writes scored outputs, but it is intentionally a research interface, not a
production monitoring system.
```

### 7. Close With The Honest Conclusion

Say:

```text
Synthetic benchmark results are strong, especially for Random Forest, but CTU-13 exposes schema and
domain shift that synthetic results alone would hide. The project is best understood as a comparative
flow-level detection study, not a production SOC detector.
```

## Optional Screen Recording Checklist

Use this if recording a short portfolio demo:

1. Show the GitHub README title and research question.
2. Scroll through the three README figures slowly.
3. Open `docs/report_draft.md` briefly to show the written research narrative.
4. Run `python -m beacon_detector.cli.score --help`.
5. End on the final conclusion in the README.

Recommended length: two to three minutes.

Avoid:

- live packet-monitoring claims
- production SOC framing
- spending time on every experiment folder
- rerunning heavy CTU evaluations during the recording
