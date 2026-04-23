from __future__ import annotations

import json
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from beacon_detector.demo_payload import DemoScenario, build_demo_payload
from beacon_detector.demo_scenarios import DEMO_SCENARIOS, DEMO_TRAIN_PATH, REPO_ROOT
from beacon_detector.ops import run_batch_score, train_random_forest_model
from beacon_detector.ops.ingest import OperationalInputFormat
from beacon_detector.ops.model import OpsModelTrainingResult, ThresholdProfileName

MAX_UPLOAD_BYTES = 512_000
UPLOAD_FILE = File(...)
UPLOAD_INPUT_FORMAT = Form(...)
UPLOAD_PROFILE = Form("balanced")
MANIFEST_PATH = REPO_ROOT / "demo-app" / "public" / "demo-scenarios" / "manifest.json"
ALLOWED_INPUT_FORMATS: tuple[OperationalInputFormat, ...] = (
    "normalized-csv",
    "zeek-conn",
    "netflow-ipfix-csv",
)
ALLOWED_PROFILES: tuple[ThresholdProfileName, ...] = (
    "conservative",
    "balanced",
    "sensitive",
)


@dataclass(frozen=True, slots=True)
class DemoServiceState:
    runtime_dir: Path
    training: OpsModelTrainingResult
    manifest: dict[str, object]


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime_dir = Path(tempfile.mkdtemp(prefix="beacon_demo_service_"))
    training = train_random_forest_model(
        train_paths=[DEMO_TRAIN_PATH],
        output_dir=runtime_dir / "model",
    )
    app.state.demo_service = DemoServiceState(
        runtime_dir=runtime_dir,
        training=training,
        manifest=_load_manifest(),
    )
    try:
        yield
    finally:
        shutil.rmtree(runtime_dir, ignore_errors=True)


def _state(request: Request) -> DemoServiceState:
    return request.app.state.demo_service


def _load_manifest() -> dict[str, object]:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {
        "default_scenario_id": DEMO_SCENARIOS[0].id,
        "scenarios": [
            {
                "id": scenario.id,
                "label": scenario.label,
                "description": scenario.description,
                "category": scenario.category,
                "input_format": scenario.input_format,
                "input_name": scenario.input_path.name,
                "profile": scenario.profile,
                "payload_path": f"/demo-scenarios/{scenario.id}.json",
            }
            for scenario in DEMO_SCENARIOS
        ],
    }


def _cors_origins() -> list[str]:
    configured = os.environ.get("BEACON_DEMO_CORS_ORIGINS", "*")
    if configured.strip() == "*":
        return ["*"]
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def _safe_filename(filename: str) -> str:
    cleaned = Path(filename).name.replace("..", "_")
    return cleaned or "uploaded_input"


app = FastAPI(title="Beacon Ops Demo Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health(request: Request) -> dict[str, object]:
    state = _state(request)
    return {
        "status": "ready",
        "service": "beacon-ops-demo",
        "default_profile": "balanced",
        "available_profiles": list(ALLOWED_PROFILES),
        "available_input_formats": list(ALLOWED_INPUT_FORMATS),
        "model_dir": str(state.training.model_dir),
        "training_data": str(DEMO_TRAIN_PATH),
        "scenario_count": len(state.manifest.get("scenarios", [])),
    }


@app.get("/scenarios")
def scenarios(request: Request) -> dict[str, object]:
    return _state(request).manifest


@app.post("/score")
async def score_upload(
    request: Request,
    file: UploadFile = UPLOAD_FILE,
    input_format: str = UPLOAD_INPUT_FORMAT,
    profile: str = UPLOAD_PROFILE,
) -> dict[str, object]:
    state = _state(request)
    if input_format not in ALLOWED_INPUT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"input_format must be one of: {', '.join(ALLOWED_INPUT_FORMATS)}",
        )
    if profile not in ALLOWED_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"profile must be one of: {', '.join(ALLOWED_PROFILES)}",
        )
    filename = file.filename or "uploaded_input"
    if filename.lower().endswith(".binetflow"):
        raise HTTPException(
            status_code=400,
            detail="CTU .binetflow is not supported in the live upload path.",
        )

    payload = await file.read(MAX_UPLOAD_BYTES + 1)
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Uploaded file exceeds the {MAX_UPLOAD_BYTES} byte demo limit.",
        )

    with tempfile.TemporaryDirectory(prefix="beacon_demo_request_") as temp_dir:
        temp_root = Path(temp_dir)
        upload_path = temp_root / _safe_filename(filename)
        upload_path.write_bytes(payload)
        try:
            score_outputs = run_batch_score(
                input_path=upload_path,
                input_format=input_format,
                output_dir=temp_root / "run",
                model_artifact_path=state.training.model_dir,
                threshold_profile=profile,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        demo_payload = build_demo_payload(
            training=state.training,
            score=score_outputs,
            scenario=DemoScenario(
                id="uploaded-run",
                label="Uploaded run",
                description=(
                    "A user-uploaded flow file scored through the operational demo "
                    "service."
                ),
                input_path=upload_path,
                input_format=input_format,
                profile=profile,
                category="uploaded",
            ),
            source_kind="uploaded",
            source_label="Uploaded file",
            source_filename=filename,
        )
        scenario_payload = demo_payload["scenario"]
        assert isinstance(scenario_payload, dict)
        scenario_payload["input_path"] = filename
        previews = demo_payload["previews"]
        assert isinstance(previews, dict)
        previews["report_md"] = previews["report_md"].replace(str(upload_path), filename)
    return demo_payload
