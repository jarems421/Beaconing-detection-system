export function normalizeWorkspacePayload(raw) {
  const scenario = raw?.scenario || {};
  const commands = raw?.commands || {};
  const metrics = Array.isArray(raw?.metrics) ? raw.metrics : [];
  const alerts = Array.isArray(raw?.alerts)
    ? raw.alerts.map((alert) => ({
        ...alert,
        reasons: Array.isArray(alert.reasons) ? alert.reasons : [],
        model_features: Array.isArray(alert.model_features)
          ? alert.model_features
          : splitPipeList(alert.features || ""),
      }))
    : [];
  const scoredFlows = Array.isArray(raw?.scored_flows) ? raw.scored_flows : [];
  const skipReasons = Array.isArray(raw?.skip_reasons) ? raw.skip_reasons : [];
  const previews = raw?.previews || {};
  return {
    scenario: {
      id: scenario.id || "unknown-scenario",
      label: scenario.label || "Scenario",
      description: scenario.description || "",
      category: scenario.category || "sample",
      input_format: scenario.input_format || "netflow-ipfix-csv",
      input_name: scenario.input_name || "input.csv",
      profile: scenario.profile || "balanced",
    },
    source: raw?.source || { kind: "sample" },
    commands: {
      score: commands.score || "",
      train_model: commands.train_model || "",
    },
    metrics,
    metricMap: Object.fromEntries(metrics.map((item) => [item.label, item.value])),
    summary: raw?.summary || {},
    alerts,
    selected_alert_id: raw?.selected_alert_id || alerts[0]?.id || null,
    scored_flows: scoredFlows,
    skip_reasons: skipReasons,
    output_files: Array.isArray(raw?.output_files) ? raw.output_files : [],
    previews,
    calibration: raw?.calibration || {},
    score_semantics: raw?.score_semantics || raw?.summary?.score_semantics || {},
    figures: Array.isArray(raw?.figures) ? raw.figures : [],
  };
}

export function splitPipeList(value) {
  return String(value)
    .split("|")
    .map((part) => part.trim())
    .filter(Boolean);
}
