"use client";

import { useWorkspaceResult } from "../lib/use-workspace-result";
import {
  EmptyResultPanel,
  humanizeFeature,
  humanizeReason,
  NoteRow,
  SelectedAlertCard,
  WorkspaceShell,
} from "./workspace-common";

export default function DemoWorkspaceExplanation() {
  const { resultData, selectedAlert, selectedFlowBreakdown, setSelectedAlertId } = useWorkspaceResult();

  return (
    <WorkspaceShell
      active="explanation"
      stepLabel="Step 3 of 5"
      title="Explanation"
      description="This is the page for the 'why'. It slows the run down, focuses on one flow, and explains the result in plain language."
      resultData={resultData}
    >
      {!resultData ? (
        <EmptyResultPanel />
      ) : (
        <section className="workspace-single-column">
          <div className="panel">
            <div className="section-head">
              <div>
                <h2>Choose a flow to explain</h2>
                <p>Pick the flow you want to understand in more detail.</p>
              </div>
            </div>
            <select
              className="search-input"
              value={selectedAlert?.id || ""}
              onChange={(event) => setSelectedAlertId(event.target.value)}
            >
              {resultData.alerts.map((alert) => (
                <option key={alert.id} value={alert.id}>
                  {alert.src} {"->"} {alert.dst}:{alert.port}/{alert.proto}
                </option>
              ))}
            </select>
          </div>

          <details className="panel collapsible-panel" open>
            <summary>Main explanation</summary>
            <div className="details-body">
              <SelectedAlertCard
                resultData={resultData}
                selectedAlert={selectedAlert}
                selectedFlowBreakdown={selectedFlowBreakdown}
              />
            </div>
          </details>

          <details className="panel collapsible-panel" open>
            <summary>Why this flow was flagged</summary>
            <div className="details-body">
              {selectedAlert ? (
                <div className="note-list">
                  {selectedAlert.reasons.map((reason) => (
                    <NoteRow key={reason} text={humanizeReason(reason)} />
                  ))}
                </div>
              ) : (
                <div className="empty-state">Select a flagged flow to see its reasons.</div>
              )}
            </div>
          </details>

          <details className="panel collapsible-panel">
            <summary>What the model paid attention to</summary>
            <div className="details-body">
              {selectedAlert ? (
                <div className="token-row">
                  {selectedAlert.model_features.map((feature) => (
                    <span className="token" key={feature}>
                      {humanizeFeature(feature)}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="empty-state">Select a flagged flow to see the feature groups.</div>
              )}
            </div>
          </details>

          <details className="panel collapsible-panel">
            <summary>How to read the scores</summary>
            <div className="details-body">
              <div className="note-list">
                <NoteRow text="The model score is a ranking signal. Higher means more suspicious, but it is not a probability." />
                <NoteRow text="The combined score is what the workspace uses to decide which flows to bring to the top of the run." />
                <NoteRow text="A flagged flow is something to review, not automatic proof of beaconing." />
              </div>
            </div>
          </details>
        </section>
      )}
    </WorkspaceShell>
  );
}
