"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { normalizeWorkspacePayload } from "../lib/demo-data-model";

const previewOrder = [
  ["report_md", "report.md"],
  ["run_summary_json", "run_summary.json"],
  ["alerts_csv", "alerts.csv"],
  ["scored_flows_csv", "scored_flows.csv"],
  ["training_report_md", "training_report.md"],
];

export default function DemoWorkspace({ initialData, manifest }) {
  const [data, setData] = useState(() => normalizeWorkspacePayload(initialData));
  const [selectedScenarioId, setSelectedScenarioId] = useState(initialData.scenario.id);
  const [query, setQuery] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(initialData.selected_alert_id);
  const [selectedPreview, setSelectedPreview] = useState("report_md");
  const [selectedProfile, setSelectedProfile] = useState(initialData.scenario.profile);
  const [selectedInputFormat, setSelectedInputFormat] = useState(initialData.scenario.input_format);
  const [uploadFile, setUploadFile] = useState(null);
  const [sampleLoading, setSampleLoading] = useState(false);
  const [uploadLoading, setUploadLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [backendState, setBackendState] = useState(
    process.env.NEXT_PUBLIC_DEMO_API_BASE_URL
      ? { status: "checking", message: "Checking live scoring service..." }
      : { status: "unavailable", message: "Live scoring is not configured for this deployment." }
  );

  const apiBaseUrl = process.env.NEXT_PUBLIC_DEMO_API_BASE_URL || "";

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
          message: `Live scoring ready (${payload.available_input_formats.join(", ")})`,
        });
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setBackendState({
          status: "unavailable",
          message: "Live scoring is unavailable right now. Sample scenarios still work.",
        });
      });
    return () => {
      active = false;
    };
  }, [apiBaseUrl]);

  const filteredAlerts = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return data.alerts;
    }
    return data.alerts.filter((alert) =>
      [alert.id, alert.src, alert.dst, alert.proto, String(alert.port), ...alert.reasons]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery)
    );
  }, [data.alerts, query]);

  const selectedAlert =
    data.alerts.find((alert) => String(alert.id) === String(selectedAlertId)) ||
    filteredAlerts[0] ||
    null;

  const selectedFlowBreakdown = useMemo(() => {
    if (!selectedAlert) {
      return null;
    }
    return data.scored_flows.find((row) =>
      row.flow.startsWith(
        `${selectedAlert.src} -> ${selectedAlert.dst}:${selectedAlert.port}/${selectedAlert.proto}`
      )
    );
  }, [data.scored_flows, selectedAlert]);

  async function handleScenarioChange(event) {
    const scenarioId = event.target.value;
    setSelectedScenarioId(scenarioId);
    setSampleLoading(true);
    setStatusMessage("");
    try {
      const scenario = manifest.scenarios.find((item) => item.id === scenarioId);
      const response = await fetch(scenario.payload_path);
      if (!response.ok) {
        throw new Error("Could not load the selected sample scenario.");
      }
      const payload = normalizeWorkspacePayload(await response.json());
      setData(payload);
      setSelectedAlertId(payload.selected_alert_id);
      setSelectedProfile(payload.scenario.profile);
      setSelectedInputFormat(payload.scenario.input_format);
      setSelectedPreview("report_md");
      setQuery("");
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setSampleLoading(false);
    }
  }

  async function handleUploadSubmit(event) {
    event.preventDefault();
    if (!uploadFile) {
      setStatusMessage("Choose a small CSV or conn.log file first.");
      return;
    }
    if (backendState.status !== "ready") {
      setStatusMessage("Live scoring is unavailable. Use the sample scenarios for now.");
      return;
    }

    setUploadLoading(true);
    setStatusMessage("");
    try {
      const formData = new FormData();
      formData.append("file", uploadFile);
      formData.append("input_format", selectedInputFormat);
      formData.append("profile", selectedProfile);
      const response = await fetch(`${apiBaseUrl}/score`, {
        method: "POST",
        body: formData,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || "Live scoring failed.");
      }
      const normalized = normalizeWorkspacePayload(payload);
      setData(normalized);
      setSelectedAlertId(normalized.selected_alert_id);
      setSelectedPreview("report_md");
      setQuery("");
      setStatusMessage(`Scored ${uploadFile.name} with the ${selectedProfile} profile.`);
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setUploadLoading(false);
    }
  }

  const metrics = data.metricMap;
  const scenarioTitle =
    data.source.kind === "uploaded"
      ? data.source.filename || data.source.label || "Uploaded run"
      : data.scenario.input_name;

  return (
    <main className="page-shell">
      <div className="top-nav">
        <div className="top-nav-brand">Beacon Ops Workspace</div>
        <div className="top-nav-links">
          <Link href="/">Overview</Link>
          <span className="top-nav-current">Workspace</span>
        </div>
      </div>

      <section className="workspace-header panel">
        <div className="workspace-header-main">
          <div className="eyebrow">Interactive inspection workspace</div>
          <h1 className="workspace-title">Sample runs and live scoring in one place.</h1>
          <p className="workspace-subtitle">
            Switch between checked-in scenarios or upload a small flow file, then inspect the
            same alerts, diagnostics, artifacts, and score interpretation surfaces.
          </p>
          <div className="workspace-status-row">
            <span className={`badge backend-${backendState.status}`}>{backendLabel(backendState)}</span>
            <span className="badge">{data.source.kind === "uploaded" ? "uploaded result" : "sample scenario"}</span>
            <span className="badge">{data.scenario.input_format}</span>
            <span className="badge">{data.scenario.profile} profile</span>
          </div>
          {statusMessage ? <div className="status-banner">{statusMessage}</div> : null}
        </div>

        <div className="workspace-header-side workspace-control-grid">
          <div className="panel workspace-control-card">
            <div className="section-head">
              <div>
                <h2>Sample scenario</h2>
                <p>Swap between checked-in runs without changing the workspace shape.</p>
              </div>
            </div>
            <label className="control-label" htmlFor="scenario-select">
              Scenario
            </label>
            <select
              id="scenario-select"
              className="search-input"
              value={selectedScenarioId}
              onChange={handleScenarioChange}
              disabled={sampleLoading}
            >
              {manifest.scenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.label}
                </option>
              ))}
            </select>
            <div className="control-help">
              {manifest.scenarios.find((scenario) => scenario.id === selectedScenarioId)?.description}
            </div>
          </div>

          <form className="panel workspace-control-card" onSubmit={handleUploadSubmit}>
            <div className="section-head">
              <div>
                <h2>Upload and score</h2>
                <p>Small-file live scoring through the separate Python service.</p>
              </div>
            </div>
            <label className="control-label" htmlFor="input-format">
              Input format
            </label>
            <select
              id="input-format"
              className="search-input"
              value={selectedInputFormat}
              onChange={(event) => setSelectedInputFormat(event.target.value)}
            >
              <option value="normalized-csv">normalized-csv</option>
              <option value="zeek-conn">zeek-conn</option>
              <option value="netflow-ipfix-csv">netflow-ipfix-csv</option>
            </select>
            <label className="control-label" htmlFor="profile-select">
              Threshold profile
            </label>
            <select
              id="profile-select"
              className="search-input"
              value={selectedProfile}
              onChange={(event) => setSelectedProfile(event.target.value)}
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
        </div>
      </section>

      <section className="workspace-grid">
        <aside className="workspace-sidebar">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Run summary</h2>
                <p>{scenarioTitle}</p>
              </div>
            </div>
            <div className="sidebar-stat-list">
              <SidebarStat label="Input rows" value={String(metrics["Input rows"] || 0)} />
              <SidebarStat label="Loaded events" value={String(metrics["Loaded events"] || 0)} />
              <SidebarStat label="Skipped rows" value={String(metrics["Skipped rows"] || 0)} />
              <SidebarStat label="Alert count" value={String(metrics["Alert count"] || 0)} />
            </div>
          </div>

          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Alerts</h2>
                <p>Ranked suspicious flows from the active result payload.</p>
              </div>
            </div>
            <input
              className="search-input"
              placeholder="Search IP, protocol, reason..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <div className="alert-list sidebar-alert-list">
              {filteredAlerts.length ? (
                filteredAlerts.map((alert) => {
                  const active = String(alert.id) === String(selectedAlert?.id);
                  return (
                    <button
                      className={`alert-card${active ? " active" : ""}`}
                      key={alert.id}
                      onClick={() => setSelectedAlertId(alert.id)}
                      type="button"
                    >
                      <div className="alert-flow">
                        {alert.src} {"->"} {alert.dst}:{alert.port}/{alert.proto}
                      </div>
                      <div className="alert-meta">
                        {alert.event_count} events | RF {Number(alert.rf_score).toFixed(3)}
                      </div>
                      <div className="badge-row">
                        <SeverityBadge severity={alert.severity} />
                        <span className="badge">{Number(alert.hybrid_score).toFixed(3)}</span>
                      </div>
                    </button>
                  );
                })
              ) : (
                <div className="empty-state">
                  No alerts exceeded the active policy for this run. Diagnostics and raw outputs are
                  still available below.
                </div>
              )}
            </div>
          </div>
        </aside>

        <section className="workspace-main">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Selected alert</h2>
                <p>The highest-value explanation surface for the current run.</p>
              </div>
            </div>

            {selectedAlert ? (
              <div className="selected-alert">
                <div className="selected-top">
                  <div>
                    <div className="detail-label">Flow</div>
                    <div className="detail-flow">
                      {selectedAlert.src} {"->"} {selectedAlert.dst}:{selectedAlert.port}/
                      {selectedAlert.proto}
                    </div>
                    <div className="badge-row">
                      <SeverityBadge severity={selectedAlert.severity} />
                      <span className="badge">{data.scenario.profile} profile</span>
                      <span className="badge">{selectedAlert.mode}</span>
                    </div>
                  </div>

                  <div className="score-stack">
                    <ScoreTile
                      label="Hybrid score"
                      value={Number(selectedAlert.hybrid_score).toFixed(3)}
                    />
                    <ScoreTile label="RF score" value={Number(selectedAlert.rf_score).toFixed(3)} />
                    <ScoreTile
                      label="Rule score"
                      value={
                        selectedFlowBreakdown
                          ? Number(selectedFlowBreakdown.rule_score).toFixed(3)
                          : "n/a"
                      }
                    />
                  </div>
                </div>

                <div className="detail-columns">
                  <div className="data-block">
                    <KeyValue label="Event count" value={selectedAlert.event_count} />
                    <KeyValue label="Total bytes" value={selectedAlert.bytes} />
                    <KeyValue label="Source ports" value={selectedAlert.src_ports_seen} />
                    <KeyValue
                      label="Predicted label"
                      value={selectedFlowBreakdown?.predicted_label || "n/a"}
                    />
                  </div>
                  <div className="data-block">
                    <div className="detail-label">Top model features</div>
                    <div className="token-row">
                      {selectedAlert.model_features.map((feature) => (
                        <span className="token" key={feature}>
                          {feature}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="reason-section">
                  <div className="detail-label">Triggered reasons</div>
                  <div className="token-row">
                    {selectedAlert.reasons.map((reason) => (
                      <span className="token" key={reason}>
                        {reason}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                This run currently has no active alert. Use the raw outputs and diagnostics below to
                inspect what happened anyway.
              </div>
            )}
          </div>

          <div className="workspace-lower-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Diagnostics</h2>
                  <p>Accepted rows, skipped rows, and recorded reasons.</p>
                </div>
              </div>
              <div className="diagnostic-topline">
                <DiagnosticPill label="Input rows" value={String(metrics["Input rows"] || 0)} />
                <DiagnosticPill
                  label="Loaded events"
                  value={String(metrics["Loaded events"] || 0)}
                />
                <DiagnosticPill
                  label="Skipped rows"
                  value={String(metrics["Skipped rows"] || 0)}
                />
              </div>
              <div className="diagnostics-grid">
                {data.skip_reasons.length ? (
                  data.skip_reasons.map((item) => (
                    <div className="diag-card" key={item.reason}>
                      <div className="diag-reason">{formatReason(item.reason)}</div>
                      <div className="diag-count">{item.count}</div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">No rows were skipped for this run.</div>
                )}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Interpretation</h2>
                  <p>Conservative wording stays attached to every result.</p>
                </div>
              </div>
              <div className="note-list">
                <NoteRow text="RF score is a ranking signal, not a calibrated probability." />
                <NoteRow text="Alerts are triage candidates, not ground truth." />
                <NoteRow text="Unsupported protocols are skipped and recorded in the run summary." />
                <NoteRow text="Low-evidence or incomplete inputs can reduce what the workflow can infer." />
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Artifacts from the run</h2>
                <p>Raw outputs from the current sample or uploaded result.</p>
              </div>
            </div>
            <div className="tab-row">
              {previewOrder.map(([key, label]) => (
                <button
                  className={`tab-button${selectedPreview === key ? " active" : ""}`}
                  key={key}
                  onClick={() => setSelectedPreview(key)}
                  type="button"
                >
                  {label}
                </button>
              ))}
            </div>
            <pre className="code-block preview-block">{data.previews[selectedPreview]}</pre>
          </div>

          <div className="workspace-lower-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Command details</h2>
                  <p>Overview only shows the score command. Full details live here.</p>
                </div>
              </div>
              <div className="note-list">
                <div>
                  <div className="overview-command-label">Train model</div>
                  <pre className="code-block compact-code">{data.commands.train_model}</pre>
                </div>
                <div>
                  <div className="overview-command-label">Score run</div>
                  <pre className="code-block compact-code">{data.commands.score}</pre>
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Technical notes</h2>
                  <p>Why the workflow is more than UI polish.</p>
                </div>
              </div>
              <div className="note-list">
                <NoteRow text="Sample scenarios and uploaded runs render through the same result model." />
                <NoteRow text="Grouped-validation-backed threshold profiles come from out-of-fold scores." />
                <NoteRow text="Ingestion diagnostics record loaded rows, skipped rows, and skip reasons." />
                <NoteRow text="The upload service wraps the existing operational scorer instead of duplicating logic." />
              </div>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}

function backendLabel(backendState) {
  if (backendState.status === "ready") {
    return "live scoring ready";
  }
  if (backendState.status === "checking") {
    return "checking live scoring";
  }
  return "live scoring unavailable";
}

function DiagnosticPill({ label, value }) {
  return (
    <div className="diagnostic-pill">
      <div className="hero-stat-label">{label}</div>
      <div className="hero-stat-value">{value}</div>
    </div>
  );
}

function KeyValue({ label, value }) {
  return (
    <div className="key-value-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function NoteRow({ text }) {
  return <div className="note-row">{text}</div>;
}

function ScoreTile({ label, value }) {
  return (
    <div className="score-tile">
      <div className="score-label">{label}</div>
      <div className="score-value">{value}</div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return <span className={`badge severity severity-${severity}`}>{severity}</span>;
}

function SidebarStat({ label, value }) {
  return (
    <div className="key-value-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatReason(reason) {
  return reason.replaceAll("_", " ");
}
