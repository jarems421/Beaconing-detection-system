"use client";

import { useWorkspaceResult } from "../lib/use-workspace-result";
import { EmptyResultPanel, previewOrder, WorkspaceShell } from "./workspace-common";

export default function DemoWorkspaceFiles() {
  const { resultData } = useWorkspaceResult();

  return (
    <WorkspaceShell
      active="files"
      stepLabel="Step 5 of 5"
      title="Files"
      description="This is the raw-output page. It keeps the report, summary JSON, CSVs, and command details in one place without crowding the main result pages."
      resultData={resultData}
    >
      {!resultData ? (
        <EmptyResultPanel />
      ) : (
        <section className="workspace-single-column">
          <details className="panel collapsible-panel" open>
            <summary>Output files</summary>
            <div className="details-body file-details-stack">
              {previewOrder.map(([key, label]) =>
                resultData.previews[key] ? (
                  <details className="panel nested-panel nested-file-panel" key={key}>
                    <summary>{label}</summary>
                    <div className="details-body">
                      <pre className="code-block preview-block compact-preview">
                        {resultData.previews[key]}
                      </pre>
                    </div>
                  </details>
                ) : null
              )}
            </div>
          </details>

          <details className="panel collapsible-panel">
            <summary>Commands behind the run</summary>
            <div className="details-body">
              <div>
                <div className="overview-command-label">Train model</div>
                <pre className="code-block compact-code">{resultData.commands.train_model}</pre>
              </div>
              <div>
                <div className="overview-command-label">Score run</div>
                <pre className="code-block compact-code">{resultData.commands.score}</pre>
              </div>
            </div>
          </details>

          <details className="panel collapsible-panel">
            <summary>Technical notes</summary>
            <div className="details-body">
              <div className="note-list">
                <div className="note-row">
                  Included inputs and uploaded files are pushed into the same workspace payload, so
                  the demo is not secretly running two different interfaces.
                </div>
                <div className="note-row">
                  The alert cutoff comes from held-out validation rather than being hand-picked on
                  the same rows used to fit the model.
                </div>
                <div className="note-row">
                  The workspace keeps the input counts and skip reasons visible so you can judge how
                  complete the run was before trusting the alert.
                </div>
              </div>
            </div>
          </details>
        </section>
      )}
    </WorkspaceShell>
  );
}
