"use client";

import { useMemo, useState } from "react";

import { useWorkspaceResult } from "../lib/use-workspace-result";
import {
  DiagnosticPill,
  EmptyResultPanel,
  formatReason,
  humanizeReason,
  SelectedAlertCard,
  SeverityBadge,
  WorkspaceShell,
} from "./workspace-common";

export default function DemoWorkspaceResults() {
  const { currentResultLabel, metrics, resultData, selectedAlert, selectedFlowBreakdown, setSelectedAlertId } =
    useWorkspaceResult();
  const [query, setQuery] = useState("");

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
  }, [query, resultData]);

  return (
    <WorkspaceShell
      active="results"
      title="Results"
      description="This page stays focused on the outcome of the run: what was flagged, what rose to the top, and a small snapshot of the run health."
      resultData={resultData}
    >
      {!resultData ? (
        <EmptyResultPanel />
      ) : (
        <section className="workspace-page-grid">
          <aside className="workspace-side-stack">
            <div className="panel">
              <div className="section-head">
                <div>
                  <h2>Flagged flows</h2>
                  <p>Pick one flow to make it the focus of the page.</p>
                </div>
              </div>
              <input
                className="search-input"
                placeholder="Search by IP, protocol, or reason..."
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
                          {alert.event_count} connections | hybrid {Number(alert.hybrid_score).toFixed(3)}
                        </div>
                        <div className="badge-row">
                          <SeverityBadge severity={alert.severity} />
                          <span className="badge">{alert.proto}</span>
                        </div>
                      </button>
                    );
                  })
                ) : (
                  <div className="empty-state">No flagged flows matched that search.</div>
                )}
              </div>
            </div>
          </aside>

          <section className="workspace-main-stack">
            <details className="panel collapsible-panel" open>
              <summary>Results summary</summary>
              <div className="details-body">
                <div className="result-summary-banner">
                  <div>
                    <div className="detail-label">Run label</div>
                    <h2>{currentResultLabel}</h2>
                    <p>
                      This is the main result view. It shows the most suspicious flow first, then
                      lets you drill down only if you need more detail.
                    </p>
                  </div>
                </div>
                <SelectedAlertCard
                  resultData={resultData}
                  selectedAlert={selectedAlert}
                  selectedFlowBreakdown={selectedFlowBreakdown}
                />
              </div>
            </details>

            <details className="panel collapsible-panel" open>
              <summary>Why this result stands out</summary>
              <div className="details-body">
                {selectedAlert ? (
                  <>
                    <div className="token-row">
                      {selectedAlert.reasons.map((reason) => (
                        <span className="token" key={reason}>
                          {humanizeReason(reason)}
                        </span>
                      ))}
                    </div>
                    <div className="note-list">
                      <div className="note-row">
                        This flow is at the top because it stayed above the active cutoff after the
                        rules and trained model were combined.
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="empty-state">
                    There is no highlighted alert in this run, so there is nothing to explain here.
                  </div>
                )}
              </div>
            </details>

            <details className="panel collapsible-panel">
              <summary>Quick diagnostics snapshot</summary>
              <div className="details-body">
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
            </details>
          </section>
        </section>
      )}
    </WorkspaceShell>
  );
}
