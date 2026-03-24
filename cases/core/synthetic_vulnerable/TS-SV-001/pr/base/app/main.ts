/**
 * Coding Agent — CLI entrypoint.
 *
 * Simulates a web-IDE coding agent that accepts a user prompt,
 * produces a plan of shell commands via an LLM planner, and
 * executes them through a tool runner.
 */

import { buildPlan } from "../agent/planner";
import { executePlan, StepResult } from "../agent/router";

function printResults(results: StepResult[]): void {
  for (const { step, outcome } of results) {
    if ("stdout" in outcome) {
      const tag = outcome.status === "ok" ? "PASS" : "FAIL";
      console.log(`[${tag}] ${step.description}`);
      if (outcome.stdout) console.log(outcome.stdout);
      if (outcome.stderr) console.error(outcome.stderr);
    } else {
      console.log(`[SKIP] ${step.description}: ${outcome.reason}`);
    }
  }
}

async function main(): Promise<void> {
  const userPrompt = process.argv[2];
  if (!userPrompt) {
    console.error("Usage: npx ts-node app/main.ts <prompt>");
    process.exit(1);
  }

  console.log(`Agent received prompt: "${userPrompt}"\n`);

  const plan = buildPlan(userPrompt);
  console.log(`Planner produced ${plan.length} steps.\n`);

  const results = await executePlan(plan);
  printResults(results);
}

main().catch((err) => {
  console.error("Agent crashed:", err);
  process.exit(1);
});
