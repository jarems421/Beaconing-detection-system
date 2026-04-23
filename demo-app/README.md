# Demo App

Next.js app for the operational beaconing demo.

## Vercel

Use these settings:

- Production Branch: `operational-system`
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
public/demo-data.json
```

Refresh that file from the repo root with:

```powershell
python scripts/build_operational_demo.py
```
