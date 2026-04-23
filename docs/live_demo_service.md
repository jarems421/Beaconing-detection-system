# Live Demo Service

This service powers the upload-and-score path for the demo workspace.

## What it does

- trains a small demo Random Forest model from `data/operational/example_train.csv` at startup
- exposes:
  - `GET /health`
  - `GET /scenarios`
  - `POST /score`
- wraps the existing operational scorer instead of duplicating scoring logic

## Run locally

```powershell
python -m beacon_detector.demo_service
```

Default bind:

```text
http://127.0.0.1:8010
```

## Frontend wiring

Set the frontend env var to the deployed service URL:

```text
NEXT_PUBLIC_DEMO_API_BASE_URL=https://your-demo-service.example.com
```

## Notes

- upload scoring is synchronous and intended for small demo files only
- supported input formats:
  - `normalized-csv`
  - `zeek-conn`
  - `netflow-ipfix-csv`
- CTU `.binetflow` is intentionally rejected from the live upload path
