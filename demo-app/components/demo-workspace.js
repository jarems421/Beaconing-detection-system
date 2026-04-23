"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { saveWorkspaceResult, useWorkspaceResult } from "../lib/use-workspace-result";
import { backendLabel, WorkspaceShell } from "./workspace-common";

export default function DemoWorkspace({ manifest }) {
  const router = useRouter();
  const defaultScenario =
    manifest.scenarios.find((scenario) => scenario.id === manifest.default_scenario_id) ||
    manifest.scenarios[0];

  const { currentResultLabel, resultData } = useWorkspaceResult();
  const [selectedScenarioId, setSelectedScenarioId] = useState(defaultScenario.id);
  const [builtInProfile, setBuiltInProfile] = useState(defaultScenario.profile);
  const [uploadProfile, setUploadProfile] = useState("balanced");
  const [uploadInputFormat, setUploadInputFormat] = useState("netflow-ipfix-csv");
  const [uploadFile, setUploadFile] = useState(null);
  const [runLoading, setRunLoading] = useState(false);
  const [uploadLoading, setUploadLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [backendState, setBackendState] = useState(
    process.env.NEXT_PUBLIC_DEMO_API_BASE_URL
      ? { status: "checking", message: "Checking live scoring service..." }
      : {
          status: "unavailable",
          message: "Live scoring is not configured here. Built-in inputs can still be opened.",
        }
  );

  const apiBaseUrl = process.env.NEXT_PUBLIC_DEMO_API_BASE_URL || "";
  const selectedScenario = useMemo(
    () => manifest.scenarios.find((scenario) => scenario.id === selectedScenarioId) || defaultScenario,
    [defaultScenario, manifest.scenarios, selectedScenarioId]
  );

  useEffect(() => {
    let active = true;
    if (!apiBaseUrl) {
      return undefined;
    }
    fetch(`${apiBaseUrl}/health`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("Live scoring service is not ready.");
        }
        return response.json();
      })
      .then((payload) => {
        if (!active) {
          return;
        }
        setBackendState({
          status: "ready",
          message: `Live scoring is available for ${payload.available_input_formats.join(", ")}.`,
        });
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setBackendState({
          status: "unavailable",
          message: "Live scoring is unavailable right now. You can still open the built-in inputs.",
        });
      });
    return () => {
      active = false;
    };
  }, [apiBaseUrl]);

  async function handleBuiltInRun(event) {
    event.preventDefault();
    setRunLoading(true);
    setStatusMessage("");
    try {
      let payload;
      if (backendState.status === "ready") {
        const response = await fetch(`${apiBaseUrl}/score-scenario`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scenario_id: selectedScenario.id,
            profile: builtInProfile,
          }),
        });
        payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || "Could not run the built-in input.");
        }
      } else {
        if (builtInProfile !== selectedScenario.profile) {
          throw new Error(
            "Live scoring is unavailable, so built-in inputs can only be opened with their checked-in default profile."
          );
        }
        const response = await fetch(selectedScenario.payload_path);
        if (!response.ok) {
          throw new Error("Could not open the built-in input result.");
        }
        payload = await response.json();
      }
      saveWorkspaceResult(payload);
      router.push("/workspace/results");
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setRunLoading(false);
    }
  }

  async function handleUploadSubmit(event) {
    event.preventDefault();
    if (!uploadFile) {
      setStatusMessage("Choose a small CSV or conn.log file first.");
      return;
    }
    if (backendState.status !== "ready") {
      setStatusMessage("Live scoring is unavailable right now, so uploaded files cannot be scored.");
      return;
    }

    setUploadLoading(true);
    setStatusMessage("");
    try {
      const formData = new FormData();
      formData.append("file", uploadFile);
      formData.append("input_format", uploadInputFormat);
      formData.append("profile", uploadProfile);
      const response = await fetch(`${apiBaseUrl}/score`, {
        method: "POST",
        body: formData,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || "Live scoring failed.");
      }
      saveWorkspaceResult(payload);
      router.push("/workspace/results");
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setUploadLoading(false);
    }
  }

  return (
    <WorkspaceShell
      active="run"
      stepLabel="Step 1 of 5"
      title="Start here"
      description="Pick one of the included inputs or upload your own small file. Once the run finishes, the rest of the workspace breaks it into separate pages instead of throwing everything at you at once."
      resultData={null}
    >
      <section className="workspace-run-grid">
        <form className="panel workspace-control-card" onSubmit={handleBuiltInRun}>
          <div className="section-head">
            <div>
              <h2>Run one of the included inputs</h2>
              <p>Good for a quick walkthrough. You click run, then the workspace opens the result pages.</p>
            </div>
          </div>
          <label className="control-label" htmlFor="scenario-select">
            Included input
          </label>
          <select
            id="scenario-select"
            className="search-input"
            value={selectedScenarioId}
            onChange={(event) => {
              const nextId = event.target.value;
              setSelectedScenarioId(nextId);
              const nextScenario =
                manifest.scenarios.find((scenario) => scenario.id === nextId) || defaultScenario;
              setBuiltInProfile(nextScenario.profile);
            }}
            disabled={runLoading}
          >
            {manifest.scenarios.map((scenario) => (
              <option key={scenario.id} value={scenario.id}>
                {scenario.label}
              </option>
            ))}
          </select>
          <div className="control-help">{selectedScenario.description}</div>
          <div className="launcher-meta-grid">
            <MetaCard label="Input format" value={selectedScenario.input_format} />
            <MetaCard label="Checked-in profile" value={selectedScenario.profile} />
          </div>
          <label className="control-label" htmlFor="built-in-profile">
            Threshold profile
          </label>
          <select
            id="built-in-profile"
            className="search-input"
            value={builtInProfile}
            onChange={(event) => setBuiltInProfile(event.target.value)}
          >
            <option value="conservative">conservative</option>
            <option value="balanced">balanced</option>
            <option value="sensitive">sensitive</option>
          </select>
          <button className="primary-link control-submit" type="submit" disabled={runLoading}>
            {runLoading ? "Running..." : "Run built-in input"}
          </button>
        </form>

        <form className="panel workspace-control-card" onSubmit={handleUploadSubmit}>
          <div className="section-head">
            <div>
              <h2>Run your own file</h2>
              <p>Good if you want to test the pipeline on your own small file instead of an included one.</p>
            </div>
          </div>
          <label className="control-label" htmlFor="upload-input-format">
            Input format
          </label>
          <select
            id="upload-input-format"
            className="search-input"
            value={uploadInputFormat}
            onChange={(event) => setUploadInputFormat(event.target.value)}
          >
            <option value="normalized-csv">normalized-csv</option>
            <option value="zeek-conn">zeek-conn</option>
            <option value="netflow-ipfix-csv">netflow-ipfix-csv</option>
          </select>
          <label className="control-label" htmlFor="upload-profile">
            Threshold profile
          </label>
          <select
            id="upload-profile"
            className="search-input"
            value={uploadProfile}
            onChange={(event) => setUploadProfile(event.target.value)}
          >
            <option value="conservative">conservative</option>
            <option value="balanced">balanced</option>
            <option value="sensitive">sensitive</option>
          </select>
          <label className="control-label" htmlFor="upload-file">
            File
          </label>
          <input
            id="upload-file"
            className="file-input"
            type="file"
            accept=".csv,.log,.connlog,.conn.log"
            onChange={(event) => setUploadFile(event.target.files?.[0] || null)}
          />
          <button
            className="primary-link control-submit"
            type="submit"
            disabled={uploadLoading || backendState.status !== "ready"}
          >
            {uploadLoading ? "Scoring..." : "Score uploaded file"}
          </button>
          <div className="control-help">{backendState.message}</div>
        </form>
      </section>

      <section className="workspace-guidance-grid">
        <div className="panel">
          <div className="section-head">
            <div>
              <h2>What happens next</h2>
              <p>After the run, you move through the result in smaller pages.</p>
            </div>
          </div>
          <div className="workflow-strip overview-strip">
            <WorkflowStep
              title="1. Results"
              body="See the main finding first, without the raw files getting in the way."
            />
            <WorkflowStep
              title="2. Explanation"
              body="Read the plain-English reasons and the model signals behind the alert."
            />
            <WorkflowStep
              title="3. Diagnostics and files"
              body="Open the skipped-row details and raw outputs only when you actually need them."
            />
          </div>
        </div>

        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Current status</h2>
              <p>This tells you whether live uploads are available and whether you already have a run loaded.</p>
            </div>
          </div>
          <div className="workspace-status-row">
            <span className={`badge backend-${backendState.status}`}>{backendLabel(backendState)}</span>
            <span className="badge">included inputs and uploads use the same result view</span>
          </div>
          {statusMessage ? <div className="status-banner">{statusMessage}</div> : null}
          {resultData ? (
            <div className="resume-card">
              <div className="detail-label">Last loaded result</div>
              <h3>{currentResultLabel}</h3>
              <p>You can jump back into the latest run without starting from scratch.</p>
              <Link className="primary-link" href="/workspace/results">
                Open last result
              </Link>
            </div>
          ) : (
            <div className="empty-state">
              No result is loaded in this browser session yet. Run something to populate the other
              pages.
            </div>
          )}
        </div>
      </section>
    </WorkspaceShell>
  );
}

function MetaCard({ label, value }) {
  return (
    <div className="proof-card compact">
      <div className="metric-label">{label}</div>
      <div className="proof-value">{value}</div>
    </div>
  );
}

function WorkflowStep({ title, body }) {
  return (
    <div className="workflow-step">
      <div className="workflow-title">{title}</div>
      <p>{body}</p>
    </div>
  );
}
