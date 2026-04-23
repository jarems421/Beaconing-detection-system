"use client";

import Link from "next/link";

const workspaceLinks = [
  { href: "/workspace", key: "run", label: "Run" },
  { href: "/workspace/results", key: "results", label: "Results" },
  { href: "/workspace/explanation", key: "explanation", label: "Explanation" },
  { href: "/workspace/diagnostics", key: "diagnostics", label: "Diagnostics" },
  { href: "/workspace/files", key: "files", label: "Files" },
];

export const previewOrder = [
  ["report_md", "report.md"],
  ["run_summary_json", "run_summary.json"],
  ["alerts_csv", "alerts.csv"],
  ["scored_flows_csv", "scored_flows.csv"],
  ["training_report_md", "training_report.md"],
];

export function WorkspaceShell({ active, title, description, resultData, children }) {
  return (
    <main className="page-shell">
      <div className="top-nav">
        <div className="top-nav-brand">Beacon Ops Demo</div>
        <div className="top-nav-links">
          <Link href="/">Overview</Link>
          <span className="top-nav-current">Workspace</span>
        </div>
      </div>

      <section className="panel workspace-view-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1 className="workspace-title workspace-view-title">{title}</h1>
          <p className="workspace-subtitle">{description}</p>
        </div>
        {resultData ? (
          <div className="workspace-status-row workspace-header-status">
            <span className="badge">
              {resultData.source.kind === "uploaded" ? "uploaded file" : "built-in input"}
            </span>
            <span className="badge">{resultData.scenario.input_format}</span>
            <span className="badge">{resultData.scenario.profile} profile</span>
          </div>
        ) : (
          <div className="workspace-header-hint">Run something first, then move between pages.</div>
        )}
      </section>

      <nav className="panel workspace-subnav">
        {workspaceLinks.map((item) => (
          <Link
            className={`workspace-subnav-link${active === item.key ? " active" : ""}`}
            href={item.href}
            key={item.key}
          >
            {item.label}
          </Link>
        ))}
      </nav>

      {resultData ? <ResultContextPanel resultData={resultData} /> : null}

      {children}
    </main>
  );
}

export function ResultContextPanel({ resultData }) {
  const resultLabel =
    resultData.source.kind === "uploaded"
      ? resultData.source.filename || "Uploaded file"
      : resultData.scenario.label;

  return (
    <section className="panel result-context-panel">
      <div>
        <div className="detail-label">Current run</div>
        <h2>{resultLabel}</h2>
        <p>
          {resultData.source.kind === "uploaded"
            ? "This view is showing the result from a file you uploaded."
            : "This view is showing the result from one of the built-in inputs."}
        </p>
      </div>
      <div className="workspace-status-row">
        <span className="badge">{resultData.scenario.input_name}</span>
        <span className="badge">{resultData.scenario.category}</span>
      </div>
    </section>
  );
}

export function EmptyResultPanel() {
  return (
    <section className="panel result-placeholder">
      <div className="section-head">
        <div>
          <h2>No run loaded yet</h2>
          <p>Start in Run, then come back here once you have scored an input.</p>
        </div>
      </div>
      <div className="workspace-empty-actions">
        <Link className="primary-link" href="/workspace">
          Go to run page
        </Link>
      </div>
    </section>
  );
}

export function SelectedAlertCard({ selectedAlert, selectedFlowBreakdown, resultData }) {
  if (!selectedAlert) {
    return (
      <div className="empty-state">
        Nothing crossed the active alert cutoff in this run. You can still use the Diagnostics page
        to see what was loaded and what was skipped.
      </div>
    );
  }

  return (
    <div className="selected-alert">
      <div className="selected-top">
        <div>
          <div className="detail-label">Flow</div>
          <div className="detail-flow">
            {selectedAlert.src} {"->"} {selectedAlert.dst}:{selectedAlert.port}/{selectedAlert.proto}
          </div>
          <div className="badge-row">
            <SeverityBadge severity={selectedAlert.severity} />
            <span className="badge">{resultData?.scenario.profile} profile</span>
            <span className="badge">{modeLabel(selectedAlert.mode)}</span>
          </div>
        </div>

        <div className="score-stack">
          <ScoreTile
            label="Combined score"
            value={Number(selectedAlert.hybrid_score).toFixed(3)}
          />
          <ScoreTile label="Model score" value={Number(selectedAlert.rf_score).toFixed(3)} />
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
    </div>
  );
}

export function DiagnosticPill({ label, value }) {
  return (
    <div className="diagnostic-pill">
      <div className="hero-stat-label">{label}</div>
      <div className="hero-stat-value">{value}</div>
    </div>
  );
}

export function KeyValue({ label, value }) {
  return (
    <div className="key-value-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function NoteRow({ text }) {
  return <div className="note-row">{text}</div>;
}

export function ScoreTile({ label, value }) {
  return (
    <div className="score-tile">
      <div className="score-label">{label}</div>
      <div className="score-value">{value}</div>
    </div>
  );
}

export function SeverityBadge({ severity }) {
  return <span className={`badge severity severity-${severity}`}>{severity}</span>;
}

export function backendLabel(backendState) {
  if (backendState.status === "ready") {
    return "live upload scoring ready";
  }
  if (backendState.status === "checking") {
    return "checking live upload scoring";
  }
  return "live upload scoring unavailable";
}

export function formatReason(reason) {
  return reason.replaceAll("_", " ");
}

export function humanizeReason(reason) {
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

export function humanizeFeature(feature) {
  const labels = {
    trimmed_interarrival_cv: "Consistency of the timing between connections",
    interarrival_within_20pct_median_fraction: "How many gaps stay close to the usual gap",
    interarrival_within_10pct_median_fraction:
      "How tightly the timing stays around one interval",
    interarrival_median_absolute_percentage_deviation:
      "How much the timing varies around its middle value",
    periodicity_score: "Overall regularity of the pattern",
    inter_arrival_cv: "Variation in time between connections",
    near_median_interarrival_fraction: "Share of timings close to the typical timing",
    dominant_interval_fraction: "How strongly one timing interval dominates",
  };
  return labels[feature] || feature.replaceAll("_", " ");
}

export function plainEnglishSummary(alert) {
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

export function modeLabel(mode) {
  if (mode === "rules_random_forest_hybrid") {
    return "rules + model";
  }
  if (mode === "rules_only") {
    return "rules only";
  }
  return mode;
}

export function labelText(value) {
  if (value === "beacon") {
    return "Flagged for review";
  }
  if (value === "benign") {
    return "Not flagged";
  }
  return value;
}
