# Operational Demo

Real demo workflow backed by checked-in scenarios, the Next.js workspace, and the same operational
scoring path used by the batch scorer.

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

- `/` for the short project overview
- `/workspace` for starting a run
- `/workspace/results` for the main finding
- `/workspace/explanation` for the plain-English explanation
- `/workspace/diagnostics` for skipped rows and run health
- `/workspace/files` for raw outputs and command details

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

This older page renders checked-in demo data generated from the operational workflow:

- the command sequence
- alerts with reasons
- `report.md` and `run_summary.json` previews
- skip diagnostics
- the conservative RF score wording used in the real outputs

## Refresh Demo Data

```powershell
python scripts/build_operational_demo.py
```
