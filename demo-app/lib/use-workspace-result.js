"use client";

import { useEffect, useMemo, useState } from "react";

import { normalizeWorkspacePayload } from "./demo-data-model";

const STORAGE_KEY = "beacon_ops_workspace_result_v1";

export function saveWorkspaceResult(raw) {
  if (typeof window === "undefined") {
    return normalizeWorkspacePayload(raw);
  }
  const normalized = normalizeWorkspacePayload(raw);
  window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
  return normalized;
}

export function clearWorkspaceResult() {
  if (typeof window === "undefined") {
    return;
  }
  window.sessionStorage.removeItem(STORAGE_KEY);
}

export function loadWorkspaceResult() {
  if (typeof window === "undefined") {
    return null;
  }
  const raw = window.sessionStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    return normalizeWorkspacePayload(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function useWorkspaceResult() {
  const [hydrated, setHydrated] = useState(false);
  const [resultData, setResultData] = useState(null);

  useEffect(() => {
    setResultData(loadWorkspaceResult());
    setHydrated(true);
  }, []);

  const metrics = resultData?.metricMap || {};

  const selectedAlert = useMemo(() => {
    if (!resultData) {
      return null;
    }
    return (
      resultData.alerts.find((alert) => String(alert.id) === String(resultData.selected_alert_id)) ||
      resultData.alerts[0] ||
      null
    );
  }, [resultData]);

  const currentResultLabel = resultData
    ? resultData.source.kind === "uploaded"
      ? resultData.source.filename || "Uploaded file"
      : resultData.scenario.label
    : null;

  const selectedFlowBreakdown = useMemo(() => {
    if (!resultData || !selectedAlert) {
      return null;
    }
    return resultData.scored_flows.find((row) =>
      row.flow.startsWith(
        `${selectedAlert.src} -> ${selectedAlert.dst}:${selectedAlert.port}/${selectedAlert.proto}`
      )
    );
  }, [resultData, selectedAlert]);

  function replaceWorkspaceResult(raw) {
    const normalized = saveWorkspaceResult(raw);
    setResultData(normalized);
    return normalized;
  }

  function setSelectedAlertId(nextAlertId) {
    setResultData((current) => {
      if (!current) {
        return current;
      }
      const next = { ...current, selected_alert_id: nextAlertId };
      saveWorkspaceResult(next);
      return next;
    });
  }

  return {
    hydrated,
    resultData,
    metrics,
    selectedAlert,
    selectedFlowBreakdown,
    currentResultLabel,
    replaceWorkspaceResult,
    setSelectedAlertId,
  };
}
