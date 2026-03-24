/** Agent router — dispatches plan steps to the appropriate tool. */

import { PlanStep } from "./planner";

export interface FetchResult {
  url: string;
  status: string;
  title: string;
}

export async function executePlan(plan: PlanStep[]): Promise<FetchResult[]> {
  const results: FetchResult[] = [];

  for (const step of plan) {
    results.push({
      url: step.url ?? "",
      status: "skipped",
      title: `Unsupported action: ${step.action}`,
    });
  }

  return results;
}
