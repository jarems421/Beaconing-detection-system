"use client";

import { useWorkspaceResult } from "../lib/use-workspace-result";
import {
  DiagnosticPill,
  EmptyResultPanel,
  formatReason,
  NoteRow,
  WorkspaceShell,
} from "./workspace-common";

export default function DemoWorkspaceDiagnostics() {
  const { metrics, resultData } = useWorkspaceResult();

  return (
    <WorkspaceShell
      active="diagnostics"
      stepLabel="Step 4 of 5"
      title="Diagnostics"
      description="This is the run-health page. Use it to see how much of the input was usable and whether anything important was skipped."
      resultData={resultData}
    >
      {!resultData ? (
        <EmptyResultPanel />
      ) : (
        <section className="workspace-single-column">
          <details className="panel collapsible-panel" open>
            <summary>Input summary</summary>
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
              <div className="note-list">
                <NoteRow text="Input rows is the total number of rows the reader saw in the file." />
                <NoteRow text="Loaded events is the number of rows that were usable after normalization." />
                <NoteRow text="Skipped rows is the number of rows that could not be used and were counted openly instead of being hidden." />
              </div>
            </div>
          </details>

          <details className="panel collapsible-panel" open>
            <summary>Skipped rows</summary>
            <div className="details-body">
              <div className="diagnostics-grid">
                {resultData.skip_reasons.length ? (
                  resultData.skip_reasons.map((item) => (
                    <div className="diag-card" key={item.reason}>
                      <div className="diag-reason">{formatReason(item.reason)}</div>
                      <div className="diag-count">{item.count}</div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">No rows were skipped in this run.</div>
                )}
              </div>
            </div>
          </details>

          <details className="panel collapsible-panel">
            <summary>What this means for interpretation</summary>
            <div className="details-body">
              <div className="note-list">
                <NoteRow text="A cleaner input usually gives a clearer result, but the workspace still shows partial runs instead of pretending they were perfect." />
                <NoteRow text="Unsupported protocols or broken rows are reported here so you can judge how complete the run really was." />
                <NoteRow text="If a run has very little usable data, treat any flagged flow as weaker evidence." />
              </div>
            </div>
          </details>
        </section>
      )}
    </WorkspaceShell>
  );
}
