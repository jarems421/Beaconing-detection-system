import DemoOverview from "../components/demo-overview";
import { loadDemoData } from "../lib/load-demo-data";

export default async function Page() {
  const data = await loadDemoData();
  return <DemoOverview data={data} />;
}
