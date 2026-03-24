/**
 * Agent router — dispatches each plan step to the appropriate tool.
 */

import { PlanStep } from "./planner";

export interface StepResult {
  step: PlanStep;
  outcome: { status: "skipped"; reason: string };
}

export async function executePlan(plan: PlanStep[]): Promise<StepResult[]> {
  const results: StepResult[] = [];

  for (const step of plan) {
    switch (step.action) {
      case "run_command": {
        results.push({
          step,
          outcome: {
            status: "skipped",
            reason: "Command execution is not supported yet",
          },
        });
        break;
      }

      // Other action types would be handled here in a full implementation.
      default:
        results.push({
          step,
          outcome: { status: "skipped", reason: `Unhandled action: ${step.action}` },
        });
    }
  }

  return results;
}
