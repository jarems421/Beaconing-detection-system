# Operational Example

This example uses tiny checked-in CSV files under `data/operational/`. They are only for smoke
testing and demonstration.

## Rules-Only Score

```powershell
beacon-ops validate --input data/operational/example_score.csv
beacon-ops score --input data/operational/example_score.csv --input-format normalized-csv --output-dir results/operational/example_rules
```

Expected outputs:

```text
results/operational/example_rules/alerts.csv
results/operational/example_rules/scored_flows.csv
results/operational/example_rules/run_summary.json
results/operational/example_rules/report.md
```

## Saved-Model Score

```powershell
beacon-ops validate --input data/operational/example_train.csv --require-label
beacon-ops train-model --train data/operational/example_train.csv --output-dir models/operational/example_rf
beacon-ops score --input data/operational/example_score.csv --input-format normalized-csv --model-artifact models/operational/example_rf --profile balanced --output-dir results/operational/example_hybrid
```

The model trained from this tiny dataset is not deployment evidence. It exists so the operational
commands can be exercised end to end from a fresh checkout.
