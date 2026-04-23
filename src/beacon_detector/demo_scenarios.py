from __future__ import annotations

from pathlib import Path

from beacon_detector.demo_payload import DemoScenario

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_TRAIN_PATH = REPO_ROOT / "data" / "operational" / "example_train.csv"
DEMO_SCENARIOS = (
    DemoScenario(
        id="suspicious-netflow",
        label="Suspicious NetFlow/IPFIX run",
        description=(
            "A checked-in NetFlow/IPFIX fixture with a strong periodic candidate plus "
            "one skipped unsupported row."
        ),
        input_path=REPO_ROOT / "data" / "operational" / "fixtures" / "netflow_demo.csv",
        input_format="netflow-ipfix-csv",
        profile="balanced",
        category="suspicious",
    ),
    DemoScenario(
        id="low-signal-zeek",
        label="Low-signal Zeek conn.log run",
        description=(
            "A short Zeek conn.log example that exercises ingestion and scoring with "
            "limited evidence and no dominant alert."
        ),
        input_path=REPO_ROOT / "data" / "operational" / "fixtures" / "zeek_parity.conn.log",
        input_format="zeek-conn",
        profile="balanced",
        category="low-signal",
    ),
    DemoScenario(
        id="messy-netflow",
        label="Messy NetFlow/IPFIX run",
        description=(
            "A small input with one unsupported protocol row to surface skip reasons "
            "and limited evidence handling."
        ),
        input_path=(
            REPO_ROOT
            / "data"
            / "operational"
            / "fixtures"
            / "netflow_unsupported_protocol.csv"
        ),
        input_format="netflow-ipfix-csv",
        profile="balanced",
        category="failure-mode",
    ),
)
