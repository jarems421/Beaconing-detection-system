import { readFile } from "node:fs/promises";
import path from "node:path";

import DemoApp from "../components/demo-app";

async function loadDemoData() {
  const dataPath = path.join(process.cwd(), "public", "demo-data.json");
  const raw = await readFile(dataPath, "utf-8");
  return JSON.parse(raw);
}

export default async function Page() {
  const data = await loadDemoData();
  return <DemoApp data={data} />;
}
