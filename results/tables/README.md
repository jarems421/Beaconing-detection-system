# Results Tables

This directory contains both curated presentation artifacts and raw/supporting experiment exports.
Nothing is deleted when the final-story layer is generated; older outputs are retained for
reproducibility.

## Most Important Folder

```text
results/tables/final_story/
```

This contains the curated report-facing tables:

- `headline_detector_comparison.csv`
- `minimum_evidence_story_table.csv`
- `ctu_three_stage_comparison.csv`
- `ctu_supervised_tradeoff_table.csv`
- `final_findings_table.csv`
- `artifact_manifest.csv`

Use this folder first when writing or presenting the project.

## Intermediate Summaries

```text
results/tables/report_ready/
```

These are broader summary tables produced from experiment exports. They are useful for audit and
traceability, but they are less curated than `final_story/`.

## Raw And Supporting Evidence

Experiment-specific folders such as these contain raw or supporting outputs:

```text
results/tables/minimum_evidence/
results/tables/shortcut_stress/
results/tables/supervised_threshold_sweep/
results/tables/ctu13_multi/
results/tables/ctu13_native/
results/tables/ctu13_supervised/
```

CTU false-positive/false-negative diagnostics and feature-importance tables are diagnostic evidence,
not headline presentation artifacts.

## Demo Or Development Outputs

Older demo/dev folders are retained for reproducibility and debugging. They are not the main report
artifacts unless specifically referenced by the final story manifest.
