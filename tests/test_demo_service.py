from __future__ import annotations

import io
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from beacon_detector.demo_service.app import app

FIXTURE_ROOT = Path("data/operational/fixtures")


class DemoServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def test_health_reports_ready_service(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ready")
        self.assertIn("balanced", payload["available_profiles"])

    def test_scenarios_lists_checked_in_examples(self) -> None:
        response = self.client.get("/scenarios")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["default_scenario_id"], "suspicious-netflow")
        self.assertGreaterEqual(len(payload["scenarios"]), 3)

    def test_score_accepts_normalized_csv_upload(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "normalized-csv", "profile": "balanced"},
            files={
                "file": (
                    "example_score.csv",
                    Path("data/operational/example_score.csv").read_bytes(),
                    "text/csv",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["source"]["kind"], "uploaded")
        self.assertEqual(payload["scenario"]["input_format"], "normalized-csv")
        self.assertIn("alerts", payload)
        self.assertIn("previews", payload)
        self.assertIn("score_semantics", payload)

    def test_score_scenario_runs_built_in_input(self) -> None:
        response = self.client.post(
            "/score-scenario",
            json={"scenario_id": "suspicious-netflow", "profile": "balanced"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["source"]["kind"], "sample")
        self.assertEqual(payload["scenario"]["id"], "suspicious-netflow")
        self.assertEqual(payload["scenario"]["input_format"], "netflow-ipfix-csv")
        self.assertGreaterEqual(payload["summary"]["loaded_events"], 1)

    def test_score_accepts_zeek_conn_upload(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "zeek-conn", "profile": "balanced"},
            files={
                "file": (
                    "zeek_parity.conn.log",
                    (FIXTURE_ROOT / "zeek_parity.conn.log").read_bytes(),
                    "text/plain",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scenario"]["input_format"], "zeek-conn")
        self.assertEqual(payload["summary"]["loaded_events"], 2)

    def test_score_accepts_netflow_upload(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "netflow-ipfix-csv", "profile": "balanced"},
            files={
                "file": (
                    "netflow_common_aliases.csv",
                    (FIXTURE_ROOT / "netflow_common_aliases.csv").read_bytes(),
                    "text/csv",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scenario"]["input_format"], "netflow-ipfix-csv")
        self.assertEqual(payload["summary"]["input_rows"], 2)

    def test_score_rejects_invalid_input_format(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "ctu-binetflow", "profile": "balanced"},
            files={"file": ("demo.csv", b"timestamp\n", "text/csv")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("input_format must be one of", response.json()["detail"])

    def test_score_rejects_empty_file(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "normalized-csv", "profile": "balanced"},
            files={"file": ("empty.csv", b"", "text/csv")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Uploaded file is empty.")

    def test_score_rejects_ctu_binetflow_upload(self) -> None:
        response = self.client.post(
            "/score",
            data={"input_format": "netflow-ipfix-csv", "profile": "balanced"},
            files={"file": ("capture.binetflow", b"ignored", "text/plain")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(".binetflow", response.json()["detail"])

    def test_score_scenario_rejects_unknown_id(self) -> None:
        response = self.client.post(
            "/score-scenario",
            json={"scenario_id": "does-not-exist", "profile": "balanced"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("Unknown built-in scenario", response.json()["detail"])

    def test_score_reports_clear_error_for_no_supported_rows(self) -> None:
        payload = io.BytesIO(
            b"first_switched,last_switched,srcaddr,srcport,dstaddr,dstport,proto,bytes,pkts\n"
            b"1767225600.000000,1767225601.000000,10.0.0.5,1111,203.0.113.10,443,1,150,3\n"
        )
        response = self.client.post(
            "/score",
            data={"input_format": "netflow-ipfix-csv", "profile": "balanced"},
            files={"file": ("unsupported_only.csv", payload, "text/csv")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("No supported operational events were loaded", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
