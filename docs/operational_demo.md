# Operational Demo

Real demo workflow backed by checked-in scenarios, the Next.js workspace, and the same operational
scoring path used elsewhere in the branch.

## Commands

```powershell
beacon-ops train-model --train data/operational/example_train.csv --output-dir models/operational/demo_rf
beacon-ops score --input data/operational/fixtures/netflow_demo.csv --input-format netflow-ipfix-csv --model-artifact models/operational/demo_rf --profile balanced --output-dir results/operational/demo
```

## Live App

The live app lives in:

```text
demo-app/
```

It has two layers:

- `/` for the high-level overview
- `/workspace` for alert investigation, diagnostics, raw outputs, and upload scoring

To run locally:

```powershell
cd demo-app
npm install
npm run dev
```

To enable live upload scoring, start the separate service:

```powershell
python -m beacon_detector.demo_service
```

Then set:

```text
NEXT_PUBLIC_DEMO_API_BASE_URL=http://127.0.0.1:8010
```

## Static Demo Page

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
