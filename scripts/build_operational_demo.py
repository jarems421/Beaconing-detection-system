from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from beacon_detector.demo_payload import build_demo_payload, build_manifest_entry
from beacon_detector.demo_scenarios import DEMO_SCENARIOS, DEMO_TRAIN_PATH
from beacon_detector.ops import run_batch_score, train_random_forest_model

ROOT = Path(__file__).resolve().parents[1]
APP_PUBLIC_DIR = ROOT / "demo-app" / "public"
APP_SCENARIO_DIR = APP_PUBLIC_DIR / "demo-scenarios"
APP_MANIFEST_PATH = APP_SCENARIO_DIR / "manifest.json"
APP_FIGURES_DIR = APP_PUBLIC_DIR / "figures"


def main() -> None:
    APP_SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        training = train_random_forest_model(
            train_paths=[DEMO_TRAIN_PATH],
            output_dir=temp_root / "model",
        )

        manifest = []
        for scenario in DEMO_SCENARIOS:
            score = run_batch_score(
                input_path=scenario.input_path,
                input_format=scenario.input_format,
                output_dir=temp_root / scenario.id,
                model_artifact_path=training.model_dir,
                threshold_profile=scenario.profile,
            )
            payload = build_demo_payload(
                training=training,
                score=score,
                scenario=scenario,
                source_kind="sample",
            )
            (APP_SCENARIO_DIR / f"{scenario.id}.json").write_text(
                json.dumps(payload, indent=2) + "\n",
                encoding="utf-8",
            )
            manifest.append(build_manifest_entry(payload))

    APP_MANIFEST_PATH.write_text(
        json.dumps(
            {
                "default_scenario_id": DEMO_SCENARIOS[0].id,
                "scenarios": manifest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _copy_figures()
    print(APP_MANIFEST_PATH)
    for scenario in DEMO_SCENARIOS:
        print(APP_SCENARIO_DIR / f"{scenario.id}.json")


def _copy_figures() -> None:
    source_dir = ROOT / "results" / "figures" / "final_story"
    APP_FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    for figure_name in (
        "01_synthetic_detector_comparison.png",
        "02_minimum_evidence_core_result.png",
        "03_ctu_three_stage_comparison.png",
    ):
        shutil.copy2(source_dir / figure_name, APP_FIGURES_DIR / figure_name)


if __name__ == "__main__":
    main()
