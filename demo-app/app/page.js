import DemoOverview from "../components/demo-overview";
import { loadDefaultDemoState } from "../lib/load-demo-data";

export default async function Page() {
  const { data } = await loadDefaultDemoState();
  return <DemoOverview data={data} />;
}
