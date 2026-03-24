/** Agent router — dispatches plan steps to the appropriate tool. */

import { PlanStep } from "./planner";

export interface ApiResult {
  url: string;
  status: string;
  summary: string;
}

export async function executePlan(plan: PlanStep[]): Promise<ApiResult[]> {
  const results: ApiResult[] = [];

  for (const step of plan) {
    results.push({
      url: step.url ?? "",
      status: "skipped",
      summary: `No tool registered for action: ${step.action}`,
    });
  }

  return results;
}
