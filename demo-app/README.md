# Demo App

Next.js app for the operational beaconing demo.

## Vercel

Use these settings:

- Production Branch: `main`
- Framework Preset: `Next.js`
- Root Directory: `demo-app`

Build and output settings can stay on auto-detect.

## Local

```powershell
cd demo-app
npm install
npm run dev
```

The app reads checked-in demo data from:

```text
public/demo-scenarios/manifest.json
public/demo-scenarios/*.json
```

Refresh that file from the repo root with:

```powershell
python scripts/build_operational_demo.py
```

To enable live upload scoring in the deployed app, set:

```text
NEXT_PUBLIC_DEMO_API_BASE_URL=https://your-demo-service.example.com
```

## App Shape

The demo is split so it is easier to read:

- `/` overview
- `/workspace` run launcher
- `/workspace/results` main finding
- `/workspace/explanation` plain-English explanation
- `/workspace/diagnostics` run health and skipped rows
- `/workspace/files` raw outputs and command details
