import Link from "next/link";

const proofChips = [
  "Run an included input or upload your own",
  "Accepts normalized CSV, Zeek, and NetFlow/IPFIX CSV",
  "Shows what was skipped and why",
  "Walks you through the result page by page",
];

export default function DemoOverview({ data }) {
  const topAlert = data.alerts[0] || null;
  const metrics = Object.fromEntries(data.metrics.map((item) => [item.label, item.value]));
  const scenario = data.scenario;
  const profile = metrics.Profile || "balanced";
  const scoreCommand = data.commands.score || "";

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
          <h1>Run a file, then walk through the result.</h1>
          <p className="hero-subtitle">
            Start with one of the included inputs or your own small file. The workspace then walks
            you through the result in separate pages for results, explanation, diagnostics, and raw
            files.
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
            <div className="overview-command-label">One example scoring command</div>
          </div>
          <pre className="code-block compact-code">{scoreCommand}</pre>
        </div>

        <div className="overview-featured panel">
          <div className="panel-kicker">Featured detection</div>
          {topAlert ? (
            <div className="featured-card">
              <div className="detail-label">One included suspicious input</div>
              <div className="featured-flow">
                {topAlert.src} {"->"} {topAlert.dst}:{topAlert.port}/{topAlert.proto}
              </div>
              <div className="badge-row">
                <SeverityBadge severity={topAlert.severity} />
                <span className="badge">{scenario.input_name}</span>
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
              <p>
                This flow rose to the top because the same source kept contacting the same
                destination on a repeated schedule, and the trained model also ranked it highly.
              </p>
              <div className="detail-label">Why this rose to the top</div>
              <div className="token-row">
                {topAlert.reasons.slice(0, 3).map((reason) => (
                  <span className="token" key={reason}>
                    {humanizeReason(reason)}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="workflow-strip overview-strip">
        <WorkflowStep
          title="1. Run"
          body="Open an included input or upload a small file and let the scorer process it."
        />
        <WorkflowStep
          title="2. Read"
          body="Use the Results and Explanation pages to understand what the run flagged and why."
        />
        <WorkflowStep
          title="3. Drill down"
          body="Open Diagnostics or Files only if you want the deeper detail behind the same run."
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
              <h2>What opens after a run</h2>
              <p>The workspace keeps the main answer first, then leaves the raw outputs for later.</p>
            </div>
          </div>
          <div className="output-card-grid">
            {data.output_files.map((file) => (
            <div className="output-card static" key={file.name}>
              <div className="file-name">{file.name}</div>
              <p>{file.description || shortOutputDescription(file.name)}</p>
            </div>
          ))}
        </div>
        </div>
      </section>

      <section className="panel overview-footer">
        <div>
          <h2>Step into the workspace</h2>
          <p>
            You start on the Run page, then move through Results, Explanation, Diagnostics, and
            Files without everything landing on one screen at once.
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

function shortOutputDescription(fileName) {
  if (fileName === "alerts.csv") {
    return "the flows that need review first";
  }
  if (fileName === "scored_flows.csv") {
    return "all flows with each score side by side";
  }
  if (fileName === "run_summary.json") {
    return "a summary of what was loaded and skipped";
  }
  return "a plain-language report of the run";
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

function humanizeReason(reason) {
  const normalized = String(reason).toLowerCase();
  if (normalized.includes("inter-arrival") || normalized.includes("periodic")) {
    return "The timing between connections is very regular.";
  }
  if (normalized.includes("size cv") || normalized.includes("constant payload")) {
    return "Each connection is sending almost the same amount of data.";
  }
  if (normalized.includes("flow duration")) {
    return "This pattern continues for long enough to be worth checking.";
  }
  if (normalized.includes("random forest score")) {
    return "The trained model also ranked this flow above its alert cutoff.";
  }
  return reason;
}
