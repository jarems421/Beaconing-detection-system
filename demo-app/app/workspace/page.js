import DemoWorkspace from "../../components/demo-workspace";
import { loadDemoData } from "../../lib/load-demo-data";

export default async function WorkspacePage() {
  const data = await loadDemoData();
  return <DemoWorkspace data={data} />;
}
