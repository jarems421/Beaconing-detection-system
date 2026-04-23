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

export default function DemoWorkspace({ manifest }) {
  const defaultScenario =
    manifest.scenarios.find((scenario) => scenario.id === manifest.default_scenario_id) ||
    manifest.scenarios[0];

  const [resultData, setResultData] = useState(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState(defaultScenario.id);
  const [builtInProfile, setBuiltInProfile] = useState(defaultScenario.profile);
  const [uploadProfile, setUploadProfile] = useState("balanced");
  const [uploadInputFormat, setUploadInputFormat] = useState("netflow-ipfix-csv");
  const [uploadFile, setUploadFile] = useState(null);
  const [query, setQuery] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [selectedPreview, setSelectedPreview] = useState("report_md");
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
          message: "Live scoring is unavailable right now. You can still run the built-in inputs.",
        });
      });
    return () => {
      active = false;
    };
  }, [apiBaseUrl]);

  const filteredAlerts = useMemo(() => {
    const alerts = resultData?.alerts || [];
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return alerts;
    }
    return alerts.filter((alert) =>
      [alert.id, alert.src, alert.dst, alert.proto, String(alert.port), ...alert.reasons]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery)
    );
  }, [resultData, query]);

  const selectedAlert =
    resultData?.alerts?.find((alert) => String(alert.id) === String(selectedAlertId)) ||
    filteredAlerts[0] ||
    null;

  const selectedFlowBreakdown = useMemo(() => {
    if (!resultData || !selectedAlert) {
      return null;
    }
    return resultData.scored_flows.find((row) =>
      row.flow.startsWith(
        `${selectedAlert.src} -> ${selectedAlert.dst}:${selectedAlert.port}/${selectedAlert.proto}`
      )
    );
  }, [resultData, selectedAlert]);

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
        setStatusMessage(`Ran the built-in input ${selectedScenario.label}.`);
      } else {
        const response = await fetch(selectedScenario.payload_path);
        if (!response.ok) {
          throw new Error("Could not open the built-in input result.");
        }
        payload = await response.json();
        setStatusMessage(
          `Opened the checked-in result for ${selectedScenario.label}. Live scoring is unavailable right now.`
        );
      }
      applyResult(payload);
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
      applyResult(payload);
      setStatusMessage(`Scored ${uploadFile.name} with the ${uploadProfile} profile.`);
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setUploadLoading(false);
    }
  }

  function applyResult(payload) {
    const normalized = normalizeWorkspacePayload(payload);
    setResultData(normalized);
    setSelectedAlertId(normalized.selected_alert_id);
    setSelectedPreview("report_md");
    setQuery("");
  }

  const metrics = resultData?.metricMap || {};
  const currentResultLabel = resultData
    ? resultData.source.kind === "uploaded"
      ? resultData.source.filename || "Uploaded file"
      : resultData.scenario.label
    : null;

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
          <div className="eyebrow">Run and inspect</div>
          <h1 className="workspace-title">Run a built-in input or score your own file.</h1>
          <p className="workspace-subtitle">
            Nothing is pre-opened here. Pick one of the built-in inputs or upload a small file, run
            it, and then inspect the result in the same workspace.
          </p>
          <div className="workspace-status-row">
            <span className={`badge backend-${backendState.status}`}>{backendLabel(backendState)}</span>
            <span className="badge">built-in inputs and uploads share one results view</span>
          </div>
          {statusMessage ? <div className="status-banner">{statusMessage}</div> : null}
        </div>
      </section>

      <section className="workspace-launcher-grid">
        <form className="panel workspace-control-card" onSubmit={handleBuiltInRun}>
          <div className="section-head">
            <div>
              <h2>Run a built-in input</h2>
              <p>Choose one of the checked-in datasets and run it in this workspace.</p>
            </div>
          </div>
          <label className="control-label" htmlFor="scenario-select">
            Built-in input
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
            <MetaCard label="Default profile" value={builtInProfile} />
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
              <p>Upload a small file and score it with the live demo service.</p>
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

      {!resultData ? (
        <section className="panel result-placeholder">
          <div className="section-head">
            <div>
              <h2>No result loaded yet</h2>
              <p>Run a built-in input or upload a file to populate this workspace.</p>
            </div>
          </div>
          <div className="workflow-strip overview-strip">
            <WorkflowStep
              title="1. Run"
              body="Start with a built-in input or your own small file."
            />
            <WorkflowStep
              title="2. Inspect"
              body="See which flows were flagged and read the plain-English explanation."
            />
            <WorkflowStep
              title="3. Drill down"
              body="Open the diagnostics or raw files only if you want the deeper detail."
            />
          </div>
        </section>
      ) : (
        <>
          <section className="panel result-summary-banner">
            <div>
              <div className="detail-label">Current result</div>
              <h2>{currentResultLabel}</h2>
              <p>
                {resultData.source.kind === "uploaded"
                  ? "This result came from a file you uploaded."
                  : "This result came from one of the built-in inputs."}
              </p>
            </div>
            <div className="workspace-status-row">
              <span className="badge">
                {resultData.source.kind === "uploaded" ? "uploaded file" : "built-in input"}
              </span>
              <span className="badge">{resultData.scenario.input_format}</span>
              <span className="badge">{resultData.scenario.profile} profile</span>
            </div>
          </section>

          <section className="workspace-grid">
            <aside className="workspace-sidebar">
              <div className="panel">
                <div className="section-head">
                  <div>
                    <h2>Run summary</h2>
                    <p>{currentResultLabel}</p>
                  </div>
                </div>
                <div className="sidebar-stat-list">
                  <SidebarStat label="Input rows" value={String(metrics["Input rows"] || 0)} />
                  <SidebarStat
                    label="Loaded events"
                    value={String(metrics["Loaded events"] || 0)}
                  />
                  <SidebarStat
                    label="Skipped rows"
                    value={String(metrics["Skipped rows"] || 0)}
                  />
                  <SidebarStat label="Alert count" value={String(metrics["Alert count"] || 0)} />
                </div>
              </div>

              <div className="panel">
                <div className="section-head">
                  <div>
                    <h2>Flagged flows</h2>
                    <p>The flows that look most suspicious in this result.</p>
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
                            {alert.event_count} connections | model{" "}
                            {Number(alert.rf_score).toFixed(3)}
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
                      diagnostics below.
                    </div>
                  )}
                </div>
              </div>
            </aside>

            <section className="workspace-main">
              <div className="panel">
                <div className="section-head">
                  <div>
                    <h2>Main finding</h2>
                    <p>The clearest explanation for the current result.</p>
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
                          <span className="badge">{resultData.scenario.profile} profile</span>
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
                    Nothing was flagged in this result, so there is no main finding card. The
                    diagnostics still explain what was loaded and what was skipped.
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
                    <DiagnosticPill
                      label="Input rows"
                      value={String(metrics["Input rows"] || 0)}
                    />
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
                    {resultData.skip_reasons.length ? (
                      resultData.skip_reasons.map((item) => (
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
                      <h2>What the model looked at</h2>
                      <p>The strongest signal groups for the selected flow.</p>
                    </div>
                  </div>
                  {selectedAlert ? (
                    <div className="token-row">
                      {selectedAlert.model_features.map((feature) => (
                        <span className="token" key={feature}>
                          {humanizeFeature(feature)}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-state">
                      Model feature notes appear here when a flagged flow is selected.
                    </div>
                  )}
                </div>

                <div className="panel">
                  <div className="section-head">
                    <div>
                      <h2>How to read this</h2>
                      <p>Short guardrails so the result stays understandable.</p>
                    </div>
                  </div>
                  <div className="note-list">
                    <NoteRow text="The model score is a ranking signal. Higher means more suspicious, but it is not a probability." />
                    <NoteRow text="A flagged flow is a candidate for review, not proof of beaconing." />
                    <NoteRow text="Rows that use unsupported protocols are skipped and counted openly instead of disappearing." />
                  </div>
                </div>
              </div>

              <details className="panel collapsible-panel">
                <summary>Show raw files from this run</summary>
                <div className="details-body">
                  <p>
                    These are the actual files produced by the run. They are useful if you want the
                    full CSV or report output, but they are not required to understand the result.
                  </p>
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
                  <pre className="code-block preview-block">{resultData.previews[selectedPreview]}</pre>
                </div>
              </details>

              <details className="panel collapsible-panel">
                <summary>Show commands and technical notes</summary>
                <div className="details-body workspace-lower-grid">
                  <div className="panel nested-panel">
                    <div className="section-head">
                      <div>
                        <h2>Command details</h2>
                        <p>The exact commands behind the current built-in result format.</p>
                      </div>
                    </div>
                    <div className="note-list">
                      <div>
                        <div className="overview-command-label">Train model</div>
                        <pre className="code-block compact-code">{resultData.commands.train_model}</pre>
                      </div>
                      <div>
                        <div className="overview-command-label">Score run</div>
                        <pre className="code-block compact-code">{resultData.commands.score}</pre>
                      </div>
                    </div>
                  </div>

                  <div className="panel nested-panel">
                    <div className="section-head">
                      <div>
                        <h2>How this works</h2>
                        <p>Short explanations of the main design choices.</p>
                      </div>
                    </div>
                    <div className="note-list">
                      <NoteRow text="Built-in inputs and uploaded files end up in the same results layout, so the demo is not two different apps." />
                      <NoteRow text="The alert cutoff comes from held-out validation instead of being chosen by hand on the same rows used to fit the model." />
                      <NoteRow text="The workspace keeps the input counts and skip reasons visible so you can tell whether the input was clean." />
                    </div>
                  </div>
                </div>
              </details>
            </section>
          </section>
        </>
      )}
    </main>
  );
}

function backendLabel(backendState) {
  if (backendState.status === "ready") {
    return "live upload scoring ready";
  }
  if (backendState.status === "checking") {
    return "checking live upload scoring";
  }
  return "live upload scoring unavailable";
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

function MetaCard({ label, value }) {
  return (
    <div className="proof-card compact">
      <div className="metric-label">{label}</div>
      <div className="proof-value">{value}</div>
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

function WorkflowStep({ title, body }) {
  return (
    <div className="workflow-step">
      <div className="workflow-title">{title}</div>
      <p>{body}</p>
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
    interarrival_median_absolute_percentage_deviation:
      "How much the timing varies around its middle value",
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
