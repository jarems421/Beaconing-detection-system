import DemoWorkspace from "../../components/demo-workspace";
import { loadDefaultDemoState } from "../../lib/load-demo-data";

export default async function WorkspacePage() {
  const { manifest, data } = await loadDefaultDemoState();
  return <DemoWorkspace initialData={data} manifest={manifest} />;
}
