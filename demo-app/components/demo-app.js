"use client";

import { useMemo, useState } from "react";

const previewOrder = [
  ["report_md", "report.md"],
  ["run_summary_json", "run_summary.json"],
  ["alerts_csv", "alerts.csv"],
  ["scored_flows_csv", "scored_flows.csv"],
  ["training_report_md", "training_report.md"],
];

const proofChips = [
  "Zeek / NetFlow-IPFIX / normalized CSV",
  "hybrid rules + RF",
  "validation-backed thresholds",
  "explainable outputs",
];

export default function DemoApp({ data }) {
  const [query, setQuery] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(data.selected_alert_id);
  const [selectedPreview, setSelectedPreview] = useState("report_md");
  const [showCommand, setShowCommand] = useState(false);

  const summary = useMemo(() => {
    try {
      return JSON.parse(data.previews.run_summary_json);
    } catch {
      return null;
    }
  }, [data.previews.run_summary_json]);

  const scenario = useMemo(() => buildScenario(data.commands), [data.commands]);

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

  const topAlert = data.alerts[0] || null;
  const profile = summary?.profile || "balanced";
  const threshold = summary?.threshold;
  const tradeoff = summary?.tradeoff_summary || {};

  return (
    <main className="page-shell">
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Operational Beaconing Detection Demo</div>
          <h1>Ingest flow data, score suspicious periodic traffic, inspect explainable alerts.</h1>
          <p className="hero-subtitle">
            Checked-in operational example using NetFlow/IPFIX-style input, hybrid rules + Random
            Forest scoring, validation-backed thresholding, and visible ingestion diagnostics.
          </p>

          <div className="hero-badges">
            {proofChips.map((chip) => (
              <Badge key={chip}>{chip}</Badge>
            ))}
          </div>

          <div className="hero-proof-grid">
            <ProofCard label="Scenario" value={scenario.fixtureName} detail={scenario.inputFormat} />
            <ProofCard label="Profile" value={profile} detail={profileMeaning(profile)} />
            <ProofCard
              label="Top result"
              value={topAlert ? `${topAlert.dst}:${topAlert.port}` : "n/a"}
              detail={topAlert ? `${topAlert.event_count} grouped events` : "no alert"}
            />
            <ProofCard
              label="Threshold"
              value={threshold === undefined ? "n/a" : Number(threshold).toFixed(2)}
              detail={summary?.selection_method || "validation policy"}
            />
          </div>

          <div className="hero-actions">
            <button
              className="secondary-button"
              onClick={() => setShowCommand((value) => !value)}
              type="button"
            >
              {showCommand ? "Hide exact CLI command" : "Show exact CLI command"}
            </button>
          </div>

          {showCommand ? <pre className="code-block hero-command">{data.commands.join("\n\n")}</pre> : null}
        </div>

        <div className="panel hero-primary-panel">
          <div className="panel-kicker">Top detection</div>
          {topAlert ? (
            <div className="hero-primary-card">
              <div>
                <div className="hero-primary-title">
                  {topAlert.src} {"->"} {topAlert.dst}:{topAlert.port}/{topAlert.proto}
                </div>
                <div className="badge-row">
                  <SeverityBadge severity={topAlert.severity} />
                  <Badge>{profile} profile</Badge>
                  <Badge>{topAlert.event_count} events</Badge>
                </div>
              </div>

              <div className="hero-score-grid">
                <ScoreTile
                  label="Hybrid score"
                  value={Number(topAlert.hybrid_score).toFixed(3)}
                />
                <ScoreTile
                  label="RF score"
                  value={Number(topAlert.rf_score).toFixed(3)}
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

              <div>
                <div className="detail-label">Why it ranked highly</div>
                <div className="token-row">
                  {topAlert.reasons.map((reason) => (
                    <span className="token" key={reason}>
                      {reason}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="workflow-strip">
        <WorkflowStep
          title="Ingest"
          body="Normalize flow records and keep skip reasons visible."
        />
        <WorkflowStep
          title="Score"
          body="Apply hybrid rules + Random Forest ranking with the selected threshold profile."
        />
        <WorkflowStep
          title="Inspect"
          body="Review alerts, artifacts, diagnostics, and interpretation notes from the same run."
        />
      </section>

      <section className="metric-strip">
        <MetricCard label="Input rows" value={metricValue(data.metrics, "Input rows")} />
        <MetricCard label="Loaded events" value={metricValue(data.metrics, "Loaded events")} />
        <MetricCard label="Skipped rows" value={metricValue(data.metrics, "Skipped rows")} />
        <MetricCard label="Alert count" value={metricValue(data.metrics, "Alert count")} />
      </section>

      <section className="primary-grid">
        <div className="panel sticky-panel">
          <div className="section-head">
            <div>
              <h2>Primary detection</h2>
              <p>What the system surfaced, and why.</p>
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
                    <Badge>{profile} profile</Badge>
                    <Badge>{selectedAlert.mode}</Badge>
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
                  <KeyValue label="Predicted label" value={selectedFlowBreakdown?.predicted_label || "n/a"} />
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

        <div className="primary-side">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Ingestion diagnostics</h2>
                <p>Accepted rows, skipped rows, and skip reasons from the checked-in run.</p>
              </div>
            </div>
            <div className="diagnostic-topline">
              <DiagnosticPill label="Input rows" value={metricValue(data.metrics, "Input rows")} />
              <DiagnosticPill
                label="Loaded events"
                value={metricValue(data.metrics, "Loaded events")}
              />
              <DiagnosticPill
                label="Skipped rows"
                value={metricValue(data.metrics, "Skipped rows")}
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
                <p>What the score means, and what it does not.</p>
              </div>
            </div>
            <div className="note-list">
              <NoteRow text="RF score is a ranking signal, not a calibrated probability." />
              <NoteRow text="Alerts are triage candidates, not ground truth." />
              <NoteRow text="Unsupported protocols are skipped and recorded." />
              <NoteRow text="Incomplete or low-evidence inputs can limit what the workflow can infer." />
            </div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="section-head">
          <div>
            <h2>Ranked alert table</h2>
            <p>Searchable suspicious flows from the checked-in operational example.</p>
          </div>
          <input
            className="search-input"
            placeholder="Search IP, protocol, reason..."
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <div className="alert-list">
          {filteredAlerts.map((alert) => {
            const active = String(alert.id) === String(selectedAlert?.id);
            return (
              <button
                className={`alert-card${active ? " active" : ""}`}
                key={alert.id}
                onClick={() => setSelectedAlertId(alert.id)}
                type="button"
              >
                <div className="alert-row">
                  <div>
                    <div className="alert-flow">
                      {alert.src} {"->"} {alert.dst}:{alert.port}/{alert.proto}
                    </div>
                    <div className="alert-meta">
                      {alert.mode} | {alert.event_count} events | {alert.bytes} bytes
                    </div>
                  </div>
                  <div className="score-block inline">
                    <div className="score-label">Hybrid</div>
                    <div className="score-value">{Number(alert.hybrid_score).toFixed(3)}</div>
                  </div>
                </div>
                <div className="badge-row">
                  <SeverityBadge severity={alert.severity} />
                  <Badge>RF {Number(alert.rf_score).toFixed(3)}</Badge>
                </div>
                <div className="token-row">
                  {alert.reasons.slice(0, 3).map((reason) => (
                    <span className="token" key={reason}>
                      {reason}
                    </span>
                  ))}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <section className="panel">
        <div className="section-head">
          <div>
            <h2>Artifacts from the run</h2>
            <p>Real outputs from the same checked-in scenario.</p>
          </div>
        </div>

        <div className="output-card-grid">
          {data.output_files.map((file) => (
            <button
              className="output-card"
              key={file.name}
              onClick={() => setSelectedPreview(tabKeyForFile(file.name))}
              type="button"
            >
              <div className="file-name">{file.name}</div>
              <p>{file.description}</p>
              <span className="output-link">View raw output</span>
            </button>
          ))}
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
      </section>

      <section className="credibility-grid">
        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Technical credibility</h2>
              <p>The engineering choices this demo is built around.</p>
            </div>
          </div>
          <div className="note-list">
            <NoteRow text="Normalized CSV, Zeek conn.log, and NetFlow/IPFIX-style CSV adapters." />
            <NoteRow text="Hybrid rules + Random Forest scoring rather than a pure opaque model." />
            <NoteRow text="Grouped-validation-backed threshold profiles selected from out-of-fold scores." />
            <NoteRow text="CLI workflow and artifacts hardened with tests and conservative score wording." />
          </div>
        </div>

        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Scored flows</h2>
              <p>Rules, RF, and hybrid ranking surfaced together.</p>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Flow</th>
                  <th>Rule</th>
                  <th>RF</th>
                  <th>Hybrid</th>
                  <th>Label</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {data.scored_flows.map((row) => (
                  <tr key={row.flow}>
                    <td>{row.flow}</td>
                    <td>{Number(row.rule_score).toFixed(3)}</td>
                    <td>{Number(row.rf_score).toFixed(3)}</td>
                    <td>{Number(row.hybrid_score).toFixed(3)}</td>
                    <td>{row.predicted_label}</td>
                    <td>{row.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="panel subdued-panel">
        <div className="section-head">
          <div>
            <h2>Research context</h2>
            <p>The operational workflow sits inside the larger benchmark and transfer story.</p>
          </div>
        </div>
        <div className="figure-grid">
          {data.figures.map((figure) => (
            <figure className="figure-card" key={figure.path}>
              <img alt={figure.title} src={figure.path} />
              <figcaption>{figure.title}</figcaption>
            </figure>
          ))}
        </div>
      </section>
    </main>
  );
}

function Badge({ children }) {
  return <span className="badge">{children}</span>;
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

function MetricCard({ label, value }) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

function NoteRow({ text }) {
  return <div className="note-row">{text}</div>;
}

function ProofCard({ detail, label, value }) {
  return (
    <div className="proof-card">
      <div className="metric-label">{label}</div>
      <div className="proof-value">{value}</div>
      <p>{detail}</p>
    </div>
  );
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

function WorkflowStep({ body, title }) {
  return (
    <div className="workflow-step">
      <div className="workflow-title">{title}</div>
      <p>{body}</p>
    </div>
  );
}

function buildScenario(commands) {
  const scoreCommand = commands.find((command) => command.includes("beacon-ops score")) || "";
  const inputPath = flagValue(scoreCommand, "--input");
  const inputFormat = flagValue(scoreCommand, "--input-format");
  return {
    fixtureName: inputPath ? inputPath.split("/").pop() : "checked-in fixture",
    inputFormat: inputFormat || "operational input",
  };
}

function flagValue(command, flag) {
  const parts = command.split(/\s+/);
  const index = parts.indexOf(flag);
  if (index === -1) {
    return "";
  }
  return parts[index + 1] || "";
}

function formatReason(reason) {
  return reason.replaceAll("_", " ");
}

function metricValue(metrics, label) {
  return String(metrics.find((item) => item.label === label)?.value || "0");
}

function profileMeaning(profile) {
  if (profile === "conservative") {
    return "fewer false positives first";
  }
  if (profile === "sensitive") {
    return "higher recall first";
  }
  return "grouped-validation F1 target";
}

function tabKeyForFile(fileName) {
  if (fileName === "run_summary.json") {
    return "run_summary_json";
  }
  if (fileName === "alerts.csv") {
    return "alerts_csv";
  }
  if (fileName === "scored_flows.csv") {
    return "scored_flows_csv";
  }
  return "report_md";
}
