# Operational Demo

Real CLI workflow backed by a checked-in NetFlow/IPFIX fixture and the same operational scoring
path used elsewhere in the branch.

## Commands

```powershell
beacon-ops train-model --train data/operational/example_train.csv --output-dir models/operational/demo_rf
beacon-ops score --input data/operational/fixtures/netflow_demo.csv --input-format netflow-ipfix-csv --model-artifact models/operational/demo_rf --profile balanced --output-dir results/operational/demo
```

## Visual Demo Page

Open:

```text
docs/operational_demo.html
```

The page renders checked-in demo data generated from the operational workflow:

- the command sequence
- alerts with reasons
- `report.md` and `run_summary.json` previews
- skip diagnostics
- the conservative RF score wording used in the real outputs

## Refresh Demo Data

```powershell
python scripts/build_operational_demo.py
```
