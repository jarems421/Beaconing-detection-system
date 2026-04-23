import Link from "next/link";

const proofChips = [
  "Zeek / NetFlow-IPFIX / normalized CSV",
  "hybrid rules + RF",
  "validation-backed thresholds",
  "explainable outputs",
];

export default function DemoOverview({ data }) {
  const topAlert = data.alerts[0] || null;
  const metrics = Object.fromEntries(data.metrics.map((item) => [item.label, item.value]));
  const scenario = buildScenario(data.commands);
  const profile = metrics.Profile || "balanced";
  const scoreCommand =
    data.commands.find((command) => command.includes("beacon-ops score")) || data.commands[0];

  return (
    <main className="page-shell">
      <div className="top-nav">
        <div className="top-nav-brand">Beacon Ops Demo</div>
        <div className="top-nav-links">
          <span className="top-nav-current">Overview</span>
          <Link className="top-nav-cta" href="/workspace">
            Open workspace
          </Link>
        </div>
      </div>

      <section className="overview-hero">
        <div className="overview-hero-copy panel">
          <div className="eyebrow">Operational Beaconing Detection Demo</div>
          <h1>One checked-in run. One credible operational workflow.</h1>
          <p className="hero-subtitle">
            Ingests Zeek, NetFlow/IPFIX, and normalized CSV flow data, scores suspicious periodic
            traffic with hybrid rules + Random Forest ranking, and produces explainable alerts with
            diagnostics.
          </p>

          <div className="chip-strip">
            {proofChips.map((chip) => (
              <span className="badge" key={chip}>
                {chip}
              </span>
            ))}
          </div>

          <div className="overview-actions">
            <Link className="primary-link" href="/workspace">
              Open demo workspace
            </Link>
            <div className="overview-command-label">Example score command</div>
          </div>
          <pre className="code-block compact-code">{scoreCommand}</pre>
        </div>

        <div className="overview-featured panel">
          <div className="panel-kicker">Featured detection</div>
          {topAlert ? (
            <div className="featured-card">
              <div className="featured-flow">
                {topAlert.src} {"->"} {topAlert.dst}:{topAlert.port}/{topAlert.proto}
              </div>
              <div className="badge-row">
                <SeverityBadge severity={topAlert.severity} />
                <span className="badge">{scenario.fixtureName}</span>
                <span className="badge">{profile} profile</span>
              </div>
              <div className="featured-score">
                <div>
                  <div className="metric-label">Hybrid score</div>
                  <div className="featured-score-value">
                    {Number(topAlert.hybrid_score).toFixed(3)}
                  </div>
                </div>
                <div>
                  <div className="metric-label">RF score</div>
                  <div className="featured-score-value small">
                    {Number(topAlert.rf_score).toFixed(3)}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Threshold</div>
                  <div className="featured-score-value small">{thresholdLabel(data)}</div>
                </div>
              </div>
              <div className="detail-label">Why this rose to the top</div>
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
      </section>

      <section className="workflow-strip overview-strip">
        <WorkflowStep
          title="Ingest"
          body="Normalize flow records and retain skip reasons instead of hiding bad inputs."
        />
        <WorkflowStep
          title="Score"
          body="Apply hybrid rules + Random Forest ranking with a validation-backed threshold profile."
        />
        <WorkflowStep
          title="Inspect"
          body="Review alerts, outputs, diagnostics, and interpretation from the same run."
        />
      </section>

      <section className="metric-strip">
        <MetricCard label="Input rows" value={String(metrics["Input rows"] || 0)} />
        <MetricCard label="Loaded events" value={String(metrics["Loaded events"] || 0)} />
        <MetricCard label="Skipped rows" value={String(metrics["Skipped rows"] || 0)} />
        <MetricCard label="Alert count" value={String(metrics["Alert count"] || 0)} />
      </section>

      <section className="overview-grid">
        <div className="panel">
          <div className="section-head">
            <div>
              <h2>What the run produced</h2>
              <p>Four default artifacts from the same checked-in scenario.</p>
            </div>
          </div>
          <div className="output-card-grid">
            {data.output_files.map((file) => (
              <div className="output-card static" key={file.name}>
                <div className="file-name">{file.name}</div>
                <p>{shortOutputDescription(file.name)}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="panel overview-footer">
        <div>
          <h2>Inspect the full run</h2>
          <p>
            Ranked alerts, detailed evidence, raw outputs, diagnostics, and score interpretation
            live in the workspace.
          </p>
        </div>
        <Link className="primary-link" href="/workspace">
          Open workspace
        </Link>
      </section>
    </main>
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

function shortOutputDescription(fileName) {
  if (fileName === "alerts.csv") {
    return "ranked suspicious flows";
  }
  if (fileName === "scored_flows.csv") {
    return "rules, RF, and hybrid scores";
  }
  if (fileName === "run_summary.json") {
    return "machine-readable diagnostics";
  }
  return "analyst-readable report";
}

function thresholdLabel(data) {
  try {
    const summary = JSON.parse(data.previews.run_summary_json);
    if (summary.threshold === undefined) {
      return "n/a";
    }
    return Number(summary.threshold).toFixed(2);
  } catch {
    return "n/a";
  }
}
