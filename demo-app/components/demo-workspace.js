"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

const previewOrder = [
  ["report_md", "report.md"],
  ["run_summary_json", "run_summary.json"],
  ["alerts_csv", "alerts.csv"],
  ["scored_flows_csv", "scored_flows.csv"],
  ["training_report_md", "training_report.md"],
];

export default function DemoWorkspace({ data }) {
  const [query, setQuery] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(data.selected_alert_id);
  const [selectedPreview, setSelectedPreview] = useState("report_md");

  const summary = useMemo(() => {
    try {
      return JSON.parse(data.previews.run_summary_json);
    } catch {
      return null;
    }
  }, [data.previews.run_summary_json]);

  const filteredAlerts = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return data.alerts;
    }
    return data.alerts.filter((alert) =>
      [
        alert.id,
        alert.src,
        alert.dst,
        alert.proto,
        String(alert.port),
        ...alert.reasons,
      ]
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

  const profile = summary?.profile || "balanced";
  const metrics = Object.fromEntries(data.metrics.map((item) => [item.label, item.value]));
  const trainCommand =
    data.commands.find((command) => command.includes("beacon-ops train-model")) || "";
  const scoreCommand =
    data.commands.find((command) => command.includes("beacon-ops score")) || "";

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
          <div className="eyebrow">Inspection workspace</div>
          <h1 className="workspace-title">One run, fully inspectable.</h1>
          <p className="workspace-subtitle">
            Ranked alerts, detailed evidence, real artifacts, skip diagnostics, and score
            interpretation from the same checked-in operational example.
          </p>
        </div>
        <div className="workspace-header-side">
          <div className="workspace-meta-grid">
            <MetaTile label="Scenario" value="netflow_demo.csv" />
            <MetaTile label="Input format" value="netflow-ipfix-csv" />
            <MetaTile label="Profile" value={String(profile)} />
            <MetaTile label="Mode" value={String(metrics.Mode || "hybrid")} />
          </div>
        </div>
      </section>

      <section className="workspace-grid">
        <aside className="workspace-sidebar">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Run summary</h2>
                <p>Core stats from the checked-in example.</p>
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
                <p>Ranked suspicious flows.</p>
              </div>
            </div>
            <input
              className="search-input"
              placeholder="Search IP, protocol, reason..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <div className="alert-list sidebar-alert-list">
              {filteredAlerts.map((alert) => {
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
              })}
            </div>
          </div>
        </aside>

        <section className="workspace-main">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Selected alert</h2>
                <p>What was ranked highly, and why.</p>
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
                      <span className="badge">{profile} profile</span>
                      <span className="badge">{selectedAlert.mode}</span>
                    </div>
                  </div>

                  <div className="score-stack">
                    <ScoreTile
                      label="Hybrid score"
                      value={Number(selectedAlert.hybrid_score).toFixed(3)}
                    />
                    <ScoreTile
                      label="RF score"
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
                    <div>{selectedAlert.features}</div>
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
              <p>No alert matches the current search.</p>
            )}
          </div>

          <div className="workspace-lower-grid">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Diagnostics</h2>
                <p>Accepted rows, skipped rows, and skip reasons.</p>
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
                {data.skip_reasons.map((item) => (
                  <div className="diag-card" key={item.reason}>
                    <div className="diag-reason">{formatReason(item.reason)}</div>
                    <div className="diag-count">{item.count}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Interpretation</h2>
                  <p>Blunt score and limitation notes.</p>
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
                <p>Raw outputs from the same checked-in scenario.</p>
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
                  <p>Exact commands used for the checked-in example and model path.</p>
                </div>
              </div>
              <div className="note-list">
                <div>
                  <div className="overview-command-label">Train model</div>
                  <pre className="code-block compact-code">{trainCommand}</pre>
                </div>
                <div>
                  <div className="overview-command-label">Score run</div>
                  <pre className="code-block compact-code">{scoreCommand}</pre>
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Technical notes</h2>
                  <p>Why this run is more than UI polish.</p>
                </div>
              </div>
              <div className="note-list">
                <NoteRow text="Real checked-in operational example, not hand-written UI values." />
                <NoteRow text="Grouped-validation-backed threshold profile chosen from out-of-fold scores." />
                <NoteRow text="Ingestion diagnostics record loaded rows, skipped rows, and skip reasons." />
                <NoteRow text="RF score is shown as a ranking signal with conservative wording." />
              </div>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
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

function MetaTile({ label, value }) {
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

function formatReason(reason) {
  return reason.replaceAll("_", " ");
}
