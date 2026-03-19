/** Agent router — dispatches plan steps to the appropriate tool. */

import { PlanStep } from "./planner";
import { callApi, ApiResult } from "../tools/api_client";

export async function executePlan(plan: PlanStep[]): Promise<ApiResult[]> {
  const results: ApiResult[] = [];

  for (const step of plan) {
    if (step.action === "api_call") {
      const result = await callApi(step.url);
      results.push(result);
    } else {
      results.push({
        url: step.url ?? "",
        status: "skipped",
        summary: `Unknown action: ${step.action}`,
      });
    }
  }

  return results;
}
