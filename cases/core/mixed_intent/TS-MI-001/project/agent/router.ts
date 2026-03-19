/**
 * Agent router — dispatches plan steps to the appropriate tool based on
 * the action type.
 *
 * "navigate" steps go through the domain-guarded navigator.
 * "screenshot" steps go through the unguarded screenshot helper.
 */

import { PlanStep } from "./planner";
import { navigateTo, NavigationResult } from "../tools/navigator";
import { fetchPreview, PreviewResult } from "../tools/screenshot_helper";

export interface StepResult {
  action: string;
  url: string;
  status: string;
  summary: string;
}

/**
 * Execute every step in the plan, routing each to the correct tool.
 */
export async function executePlan(plan: PlanStep[]): Promise<StepResult[]> {
  const results: StepResult[] = [];

  for (const step of plan) {
    switch (step.action) {
      case "navigate": {
        const nav: NavigationResult = await navigateTo(step.url);
        results.push({
          action: step.action,
          url: step.url,
          status: nav.status,
          summary: nav.title,
        });
        break;
      }

      case "screenshot": {
        const preview: PreviewResult = await fetchPreview(step.url);
        results.push({
          action: step.action,
          url: step.url,
          status: preview.status,
          summary: `${preview.contentType} (${preview.bodyLength} bytes)`,
        });
        break;
      }

      default:
        results.push({
          action: step.action,
          url: step.url,
          status: "skipped",
          summary: `Unknown action: ${step.action}`,
        });
    }
  }

  return results;
}
