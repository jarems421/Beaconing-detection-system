import { readFile } from "node:fs/promises";
import path from "node:path";

const scenarioRoot = path.join(process.cwd(), "public", "demo-scenarios");

export async function loadDemoManifest() {
  const raw = await readFile(path.join(scenarioRoot, "manifest.json"), "utf-8");
  return JSON.parse(raw);
}

export async function loadScenarioPayload(id) {
  const raw = await readFile(path.join(scenarioRoot, `${id}.json`), "utf-8");
  return JSON.parse(raw);
}

export async function loadDefaultDemoState() {
  const manifest = await loadDemoManifest();
  const defaultScenarioId = manifest.default_scenario_id;
  const data = await loadScenarioPayload(defaultScenarioId);
  return { manifest, data };
}

export async function loadWorkspaceManifest() {
  return loadDemoManifest();
}
