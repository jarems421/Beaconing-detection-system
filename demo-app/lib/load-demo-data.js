import { readFile } from "node:fs/promises";
import path from "node:path";

export async function loadDemoData() {
  const dataPath = path.join(process.cwd(), "public", "demo-data.json");
  const raw = await readFile(dataPath, "utf-8");
  return JSON.parse(raw);
}
