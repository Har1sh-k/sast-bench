/**
 * Agent router — dispatches each plan step to the appropriate tool.
 */

import { PlanStep } from "./planner";
import { runCommand, CommandResult } from "../tools/command_runner";

export interface StepResult {
  step: PlanStep;
  outcome: CommandResult | { status: "skipped"; reason: string };
}

export async function executePlan(plan: PlanStep[]): Promise<StepResult[]> {
  const results: StepResult[] = [];

  for (const step of plan) {
    switch (step.action) {
      case "run_command": {
        if (!step.command) {
          results.push({
            step,
            outcome: { status: "skipped", reason: "No command provided" },
          });
          break;
        }
        // Pass the model-generated command directly to the runner.
        const outcome = await runCommand(step.command);
        results.push({ step, outcome });
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
