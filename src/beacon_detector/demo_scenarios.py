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
            "A sample network-flow file where one machine talks to the same destination "
            "at very regular intervals. One row is skipped because it uses an unsupported protocol."
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
            "A short Zeek example with only a little evidence. It still scores, "
            "but the result is much less convincing than the suspicious sample."
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
            "A small messy input that shows how the system handles incomplete or unsupported rows "
            "without failing silently."
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
