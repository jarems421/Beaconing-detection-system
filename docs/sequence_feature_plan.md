# Sequence-Aware Feature Plan

The minimum-evidence study suggests that aggregate flow features lose separability when evasive
beaconing has too few events, high timing jitter, and size variation that overlaps with benign
traffic. Sequence-aware features are the next feature direction to explore.

This is a design note, not an implementation.

## Motivation

Current features summarize an entire flow. That is useful and readable, but it can hide ordering
information such as:

```text
whether intervals stabilize after an initial noisy period
whether gaps alternate between two machine-like cadences
whether bursts become more regular over time
whether early-flow evidence differs from full-flow evidence
```

The hardest `time_size_jittered` failures suggest the model may need richer partial-flow and
ordered-gap information rather than more broad aggregate statistics.

## Prefix-Based Partial Detection

Evaluate features on flow prefixes:

```text
first 3 events
first 5 events
first 7 events
first 9 events
first 12 events
full flow
```

This would connect directly to the minimum-evidence result and make early-detection tradeoffs more
explicit.

Useful outputs:

```text
detection rate by prefix length
probability/score by prefix length
first prefix where detector becomes confident
false positives by benign profile at each prefix length
```

## Rolling Timing Stability

Candidate rolling features:

```text
rolling median inter-arrival
rolling inter-arrival CV
rolling gap-range ratio
number of windows with stable timing
trend in timing stability across the flow
```

These may detect machine-like behaviour that is not visible from one global variance statistic.

## Ordered Gap-Shape Features

Candidate ordered-gap descriptors:

```text
adjacent gap ratio sequence
longest run of similar adjacent gaps
number of direction changes in gap size
alternating short/long cadence indicator
early-vs-late median gap difference
```

These are still interpretable and avoid jumping to sequence models too early.

## Burst Progression Features

For bursty traffic, consider:

```text
burst start-time regularity
sleep duration trend
burst size trend
within-burst gap consistency over time
number of repeated burst shapes
```

This could help distinguish bursty C2 from benign bursty sessions.

## Evaluation Plan

The sequence-aware feature work should be judged against:

```text
minimum-evidence study
shortcut/overlap stress suite
held-out time_size_jittered validation
normal_keepalive / normal_telemetry / normal_bursty_session false positives
```

The key question is not whether new features improve the easy benchmark. The key question is
whether they improve low-event evasive regimes without creating many benign repeated-traffic false
positives.

## What Not To Do First

Avoid starting with deep sequence models. The project should first test whether interpretable
sequence-aware features recover useful signal. If they do not, that becomes stronger evidence that
the flow-level representation itself is reaching a limit.
