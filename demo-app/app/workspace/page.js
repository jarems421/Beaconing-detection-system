import DemoWorkspace from "../../components/demo-workspace";
import { loadWorkspaceManifest } from "../../lib/load-demo-data";

export default async function WorkspacePage() {
  const manifest = await loadWorkspaceManifest();
  return <DemoWorkspace manifest={manifest} />;
}
