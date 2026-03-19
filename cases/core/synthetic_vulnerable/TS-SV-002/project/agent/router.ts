/** Agent router — dispatches plan steps to the appropriate tool. */

import { PlanStep } from "./planner";
import { fetchUrl, FetchResult } from "../tools/url_fetcher";

export async function executePlan(plan: PlanStep[]): Promise<FetchResult[]> {
  const results: FetchResult[] = [];

  for (const step of plan) {
    if (step.action === "fetch_url") {
      const result = await fetchUrl(step.url);
      results.push(result);
    } else {
      results.push({
        url: step.url ?? "",
        status: "skipped",
        title: `Unknown action: ${step.action}`,
      });
    }
  }

  return results;
}
