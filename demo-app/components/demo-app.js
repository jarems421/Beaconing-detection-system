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

  const topAlert = data.alerts[0] || null;
  const threshold = summary?.threshold;
  const tradeoff = summary?.tradeoff_summary || {};
  const profile = summary?.profile || "balanced";

  return (
    <main className="page-shell">
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Beacon Ops Live Demo</div>
          <h1>Beaconing detection, scored end to end.</h1>
          <p className="hero-subtitle">
            Checked-in NetFlow/IPFIX traffic, hybrid rules and Random Forest scoring, visible skip
            diagnostics, and analyst-readable outputs in one run.
          </p>

          <div className="hero-badges">
            <Badge>NetFlow/IPFIX</Badge>
            <Badge>Rules + RF</Badge>
            <Badge>{profile} profile</Badge>
            <Badge>Live artifacts</Badge>
          </div>

          <div className="hero-stat-strip">
            <HeroStat
              label="Alert count"
              value={String(data.metrics.find((item) => item.label === "Alert count")?.value || 0)}
            />
            <HeroStat
              label="Loaded events"
              value={String(
                data.metrics.find((item) => item.label === "Loaded events")?.value || 0
              )}
            />
            <HeroStat
              label="Skipped rows"
              value={String(
                data.metrics.find((item) => item.label === "Skipped rows")?.value || 0
              )}
            />
            <HeroStat
              label="Threshold"
              value={threshold === undefined ? "n/a" : Number(threshold).toFixed(2)}
            />
          </div>
        </div>

        <div className="hero-side">
          <div className="panel hero-alert-panel">
            <div className="panel-kicker">Top candidate</div>
            {topAlert ? (
              <div className="hero-top-alert">
                <div className="hero-top-flow">
                  {topAlert.src} {"->"} {topAlert.dst}:{topAlert.port}/{topAlert.proto}
                </div>
                <div className="hero-top-meta">
                  <SeverityBadge severity={topAlert.severity} />
                  <Badge>{topAlert.event_count} events</Badge>
                </div>
                <div className="hero-top-score">
                  <span>Hybrid score</span>
                  <strong>{Number(topAlert.hybrid_score).toFixed(3)}</strong>
                </div>
                <div className="token-row">
                  {topAlert.reasons.slice(0, 3).map((reason) => (
                    <span className="token" key={reason}>
                      {reason}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>

          <div className="panel command-panel">
            <div className="panel-kicker">Command path</div>
            <pre className="code-block">{data.commands.join("\n\n")}</pre>
          </div>
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
              <h2>Scoring policy</h2>
              <p>Batch-first scoring with saved-model loading and thresholded ranking.</p>
            </div>
          </div>
          <div className="policy-list">
            <PolicyRow label="Mode" value={String(data.metrics.find((item) => item.label === "Mode")?.value || "hybrid")} />
            <PolicyRow label="Profile" value={profile} />
            <PolicyRow
              label="Precision"
              value={tradeoff.precision === undefined ? "n/a" : Number(tradeoff.precision).toFixed(2)}
            />
            <PolicyRow
              label="Recall"
              value={tradeoff.recall === undefined ? "n/a" : Number(tradeoff.recall).toFixed(2)}
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
              <h2>Score semantics</h2>
              <p>Ranking language stays conservative and tied to the actual artifact metadata.</p>
            </div>
          </div>
          <div className="callout">
            <div className="callout-label">Calibration status</div>
            <div className="callout-value">{data.calibration.status}</div>
            <div className="callout-label">Brier score</div>
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
              <p>Suspicious grouped flows from the checked-in demo fixture.</p>
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
          <div className="panel sticky-panel">
            <div className="section-head">
              <div>
                <h2>Selected alert</h2>
                <p>Flow detail, evidence, and model context.</p>
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
                  <div className="score-stack">
                    <div className="score-block emphasis">
                      <div className="score-label">Hybrid score</div>
                      <div className="score-value">
                        {Number(selectedAlert.hybrid_score).toFixed(3)}
                      </div>
                    </div>
                    <div className="score-block compact">
                      <div className="score-label">RF score</div>
                      <div className="score-mini-value">
                        {Number(selectedAlert.rf_score).toFixed(3)}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="detail-columns">
                  <div className="data-block">
                    <KeyValue label="Event count" value={selectedAlert.event_count} />
                    <KeyValue label="Total bytes" value={selectedAlert.bytes} />
                    <KeyValue label="Source ports" value={selectedAlert.src_ports_seen} />
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
                  <div className="diag-reason">{formatReason(item.reason)}</div>
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

function HeroStat({ label, value }) {
  return (
    <div className="hero-stat">
      <div className="hero-stat-label">{label}</div>
      <div className="hero-stat-value">{value}</div>
    </div>
  );
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

function PolicyRow({ label, value }) {
  return (
    <div className="policy-row">
      <span>{label}</span>
      <strong>{value}</strong>
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

function formatReason(reason) {
  return reason.replaceAll("_", " ");
}
