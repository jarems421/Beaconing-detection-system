"use client";

import { useMemo, useState } from "react";

const previewOrder = [
  ["report_md", "report.md"],
  ["run_summary_json", "run_summary.json"],
  ["alerts_csv", "alerts.csv"],
  ["scored_flows_csv", "scored_flows.csv"],
  ["training_report_md", "training_report.md"],
];

export default function DemoApp({ data }) {
  const [query, setQuery] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(data.selected_alert_id);
  const [selectedPreview, setSelectedPreview] = useState("report_md");

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

  return (
    <main className="page-shell">
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Operational Demo App</div>
          <h1>{data.title}</h1>
          <p className="hero-subtitle">{data.subtitle}</p>
          <div className="hero-badges">
            <Badge>NetFlow/IPFIX</Badge>
            <Badge>Hybrid scoring</Badge>
            <Badge>Threshold profiles</Badge>
            <Badge>Diagnostics</Badge>
          </div>
        </div>
        <div className="panel command-panel">
          <div className="panel-kicker">Command path</div>
          <pre className="code-block">{data.commands.join("\n\n")}</pre>
        </div>
      </section>

      <section className="metrics-grid">
        {data.metrics.map((metric) => (
          <div className="metric-card" key={metric.label}>
            <div className="metric-label">{metric.label}</div>
            <div className="metric-value">{String(metric.value)}</div>
          </div>
        ))}
      </section>

      <section className="three-up">
        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Workflow</h2>
              <p>Ingest, score, and inspect in one batch-oriented path.</p>
            </div>
          </div>
          <div className="workflow-list">
            <WorkflowCard
              title="Ingest"
              text="Normalize logs into the shared scoring contract with visible skip handling."
            />
            <WorkflowCard
              title="Score"
              text="Combine interpretable rules with a saved Random Forest score."
            />
            <WorkflowCard
              title="Inspect"
              text="Review flagged flows, report outputs, and score semantics together."
            />
          </div>
        </div>

        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Output files</h2>
              <p>Default artifacts written by the scoring command.</p>
            </div>
          </div>
          <div className="file-list">
            {data.output_files.map((file) => (
              <div className="file-card" key={file.name}>
                <div className="file-name">{file.name}</div>
                <p>{file.description}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="section-head">
            <div>
              <h2>Calibration note</h2>
              <p>Conservative wording stays attached to the model outputs.</p>
            </div>
          </div>
          <div className="callout">
            <div className="callout-label">status</div>
            <div className="callout-value">{data.calibration.status}</div>
            <div className="callout-label">brier_score</div>
            <div className="callout-value">
              {Number(data.calibration.brier_score).toFixed(4)}
            </div>
            <p>{data.calibration.recommendation}</p>
          </div>
        </div>
      </section>

      <section className="content-grid">
        <div className="panel alerts-panel">
          <div className="section-head">
            <div>
              <h2>Flagged flows</h2>
              <p>Real alerts generated from the checked-in demo fixture.</p>
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
                        {alert.mode} | {alert.event_count} events
                      </div>
                    </div>
                    <div className="score-block">
                      <div className="score-label">Hybrid</div>
                      <div className="score-value">
                        {Number(alert.hybrid_score).toFixed(3)}
                      </div>
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
        </div>

        <div className="detail-stack">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Selected alert</h2>
                <p>Flow context, scoring detail, and triggered reasons.</p>
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
                      <Badge>{selectedAlert.mode}</Badge>
                    </div>
                  </div>
                  <div className="score-block">
                    <div className="score-label">RF score</div>
                    <div className="score-value">
                      {Number(selectedAlert.rf_score).toFixed(3)}
                    </div>
                  </div>
                </div>

                <div className="detail-columns">
                  <div className="data-block">
                    <div>event_count: {selectedAlert.event_count}</div>
                    <div>total_bytes: {selectedAlert.bytes}</div>
                    <div>src_ports_seen: {selectedAlert.src_ports_seen}</div>
                    <div>hybrid_score: {Number(selectedAlert.hybrid_score).toFixed(3)}</div>
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

          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Ingestion diagnostics</h2>
                <p>Accepted rows, skipped rows, and skip reasons stay visible.</p>
              </div>
            </div>
            <div className="diagnostics-grid">
              {data.skip_reasons.map((item) => (
                <div className="diag-card" key={item.reason}>
                  <div className="diag-reason">{item.reason}</div>
                  <div className="diag-count">{item.count}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="section-head">
          <div>
            <h2>Output previews</h2>
            <p>Analyst-readable and machine-readable artifacts from the same run.</p>
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
      </section>

      <section className="panel">
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
      </section>

      <section className="panel">
        <div className="section-head">
          <div>
            <h2>Research context</h2>
            <p>Operational workflow, benchmark results, and transfer limits in one repo.</p>
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

function SeverityBadge({ severity }) {
  return <span className={`badge severity severity-${severity}`}>{severity}</span>;
}

function WorkflowCard({ text, title }) {
  return (
    <div className="workflow-card">
      <div className="workflow-title">{title}</div>
      <p>{text}</p>
    </div>
  );
}
