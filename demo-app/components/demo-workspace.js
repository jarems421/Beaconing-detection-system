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
      : {
          status: "unavailable",
          message: "Live scoring is not configured for this deployment, but the sample runs still work.",
        }
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
          message: `Live scoring is available for ${payload.available_input_formats.join(", ")}.`,
        });
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setBackendState({
          status: "unavailable",
          message: "Live scoring is unavailable right now. The sample scenarios still work.",
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
          <h1 className="workspace-title">See what the system found and why it found it.</h1>
          <p className="workspace-subtitle">
            Pick a sample run or upload a small file. The page will show the suspicious flows, the
            reasons they were flagged, the rows that were skipped, and the files produced by the run.
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
                <p>Switch between prepared examples without changing how the page works.</p>
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
                <p>Upload a small file and score it with the same backend used for the sample runs.</p>
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
                <p>The flows that look most suspicious in this run.</p>
              </div>
            </div>
            <input
              className="search-input"
              placeholder="Search IP address, protocol, or reason..."
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
                        {alert.event_count} connections | model {Number(alert.rf_score).toFixed(3)}
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
                  No flow crossed the current alert cutoff in this run. You can still inspect the
                  diagnostics and raw outputs below.
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
                <p>The clearest plain-language explanation for the current run.</p>
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
                      <span className="badge">{modeLabel(selectedAlert.mode)}</span>
                    </div>
                  </div>

                  <div className="score-stack">
                    <ScoreTile
                      label="Combined score"
                      value={Number(selectedAlert.hybrid_score).toFixed(3)}
                    />
                    <ScoreTile
                      label="Model score"
                      value={Number(selectedAlert.rf_score).toFixed(3)}
                    />
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
                    <div className="detail-label">In plain English</div>
                    <div className="note-list plain-note-list">
                      {plainEnglishSummary(selectedAlert).map((line) => (
                        <NoteRow key={line} text={line} />
                      ))}
                    </div>
                  </div>
                  <div className="data-block">
                    <KeyValue label="Event count" value={selectedAlert.event_count} />
                    <KeyValue label="Total bytes" value={selectedAlert.bytes} />
                    <KeyValue label="Source ports seen" value={selectedAlert.src_ports_seen} />
                    <KeyValue
                      label="Final decision"
                      value={labelText(selectedFlowBreakdown?.predicted_label || "n/a")}
                    />
                  </div>
                  <div className="data-block">
                    <div className="detail-label">What the model paid attention to</div>
                    <div className="token-row">
                      {selectedAlert.model_features.map((feature) => (
                        <span className="token" key={feature}>
                          {humanizeFeature(feature)}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="reason-section">
                  <div className="detail-label">Why this flow was flagged</div>
                  <div className="token-row">
                    {selectedAlert.reasons.map((reason) => (
                      <span className="token" key={reason}>
                        {humanizeReason(reason)}
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
                <p>What was accepted, what was skipped, and why.</p>
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
                <p>How to read these results without overclaiming.</p>
              </div>
            </div>
            <div className="note-list">
                <NoteRow text="The model score is a ranking signal. Higher means more suspicious, but it is not a probability." />
                <NoteRow text="A flagged flow is a candidate for review, not proof of beaconing." />
                <NoteRow text="Rows that use unsupported protocols are skipped and counted openly instead of disappearing." />
                <NoteRow text="Small or messy inputs can make the result less certain, even when the page still shows a score." />
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Artifacts from the run</h2>
                <p>The actual files produced by this run.</p>
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
                  <p>The exact commands behind the sample run.</p>
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
                  <h2>How this works</h2>
                  <p>Short explanations of the main design choices.</p>
                </div>
              </div>
              <div className="note-list">
                <NoteRow text="Sample runs and uploaded runs are shown through the same page layout, so the demo is not a separate mock path." />
                <NoteRow text="The alert cutoff comes from held-out validation results rather than being chosen by hand for the same rows used to fit the model." />
                <NoteRow text="The page always keeps the ingestion counts and skip reasons visible so you can see whether the input was clean." />
                <NoteRow text="The upload service uses the existing scorer from the project instead of re-implementing a second version just for the demo." />
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

function humanizeReason(reason) {
  const normalized = String(reason).toLowerCase();
  if (normalized.includes("inter-arrival") || normalized.includes("periodic")) {
    return "The timing between connections is unusually regular.";
  }
  if (normalized.includes("size cv") || normalized.includes("constant payload")) {
    return "The amount of data sent each time is very similar.";
  }
  if (normalized.includes("flow duration")) {
    return "The repeated pattern lasts long enough to be worth investigating.";
  }
  if (normalized.includes("random forest score")) {
    return "The trained model also ranked this flow above its alert cutoff.";
  }
  if (normalized.includes("sustained_repeated_communication")) {
    return "The same source and destination keep talking over time.";
  }
  return reason.replaceAll("_", " ");
}

function humanizeFeature(feature) {
  const labels = {
    trimmed_interarrival_cv: "Consistency of the timing between connections",
    interarrival_within_20pct_median_fraction: "How many gaps stay close to the usual gap",
    interarrival_within_10pct_median_fraction: "How tightly the timing stays around one interval",
    interarrival_median_absolute_percentage_deviation: "How much the timing varies around its middle value",
    periodicity_score: "Overall regularity of the pattern",
    inter_arrival_cv: "Variation in time between connections",
    near_median_interarrival_fraction: "Share of timings close to the typical timing",
    dominant_interval_fraction: "How strongly one timing interval dominates",
  };
  return labels[feature] || feature.replaceAll("_", " ");
}

function plainEnglishSummary(alert) {
  const lines = [];
  if (alert.reasons.some((reason) => /inter-arrival|periodic/i.test(reason))) {
    lines.push("This host is contacting the same destination at a very steady rhythm.");
  }
  if (alert.reasons.some((reason) => /size cv|constant payload/i.test(reason))) {
    lines.push("Each contact looks similar in size, which can happen in automated check-ins.");
  }
  if (alert.reasons.some((reason) => /random forest score/i.test(reason))) {
    lines.push("The trained model independently ranks this flow as suspicious as well.");
  }
  if (!lines.length) {
    lines.push("This flow was kept for review because it still ranked above the active cutoff.");
  }
  return lines;
}

function modeLabel(mode) {
  if (mode === "rules_random_forest_hybrid") {
    return "rules + model";
  }
  if (mode === "rules_only") {
    return "rules only";
  }
  return mode;
}

function labelText(value) {
  if (value === "beacon") {
    return "Flagged for review";
  }
  if (value === "benign") {
    return "Not flagged";
  }
  return value;
}
