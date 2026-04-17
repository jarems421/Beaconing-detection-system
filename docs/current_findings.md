# Final Findings

This document summarizes the final project findings. Detailed narrative lives in
`docs/report_draft.md`; curated presentation artifacts live under `results/tables/final_story/` and
`results/figures/final_story/`.

## Headline Findings

1. Synthetic flow-level detection works well under controlled conditions, especially with Random
   Forest.
2. The frozen rule baseline remains the strongest interpretable reference.
3. Hard benign profiles and shortcut-overlap tests expose limits that a standard synthetic grid can
   hide.
4. Minimum evidence is the central research finding: easy regimes need little history, while evasive
   low-event time-and-size jittered regimes need much more.
5. CTU-13 exposes schema and domain shift; synthetic transfer alone is not enough.
6. CTU-native modelling is more honest than forcing CTU through synthetic features, but it is still
   not deployment proof.

## CTU Story Labels

The public-data evidence must stay split into three labels:

```text
Synthetic direct transfer to CTU
CTU-native unsupervised evaluation
Within-CTU supervised evaluation
```

Synthetic direct transfer shows that synthetic-trained RF can detect many CTU botnet-labelled flows,
but with high false positives. CTU-native unsupervised evaluation uses `.binetflow` fields directly
with LOF and a benign CTU reference. Within-CTU supervised evaluation trains CTU-native Logistic
Regression and Random Forest with scenario-aware splits.

These stages answer different questions and should not be collapsed into one score.

## Final Conclusion

Synthetic benchmark results are strong, especially for Random Forest, but the most important research finding is the minimum-evidence result: easy beaconing regimes can be detected with little flow history, while evasive low-event, high-jitter, size-overlapping regimes require substantially more evidence. CTU-13 validation exposes schema and domain shift that synthetic results alone would hide. CTU-native modelling is a more honest public-data path than forcing CTU bidirectional rows through synthetic-style features, but it is still not deployment proof. This project is a comparative flow-level detection study, not a production SOC detector.

## Remaining Limitations

- Synthetic data is not real traffic.
- CTU-13 validation is useful but label-policy sensitive.
- Background-as-benign sensitivity remains intentionally separate from headline CTU results.
- The current feature representation may lose separability when flows have too few events.
- The local scorer is a research interface, not a production SOC detector.
