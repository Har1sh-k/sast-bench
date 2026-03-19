/**
 * Consumer Browser Assistant — main CLI entrypoint.
 *
 * Accepts a product search query, generates a browsing plan via the LLM
 * planner, and executes the plan through the agent router, which
 * dispatches navigation and screenshot tasks to the appropriate tools.
 */

import { createBrowsingPlan } from "../agent/planner";
import { executePlan } from "../agent/router";

async function main(query: string): Promise<void> {
  console.log(`Browser Assistant — searching for: ${query}\n`);

  const plan = createBrowsingPlan(query);
  console.log(`Generated ${plan.length} browsing steps.\n`);

  const results = await executePlan(plan);

  for (const result of results) {
    const icon = result.status === "ok" ? "+" : result.status === "blocked" ? "x" : "!";
    console.log(`[${icon}] (${result.action}) ${result.url}`);
    console.log(`    ${result.summary}\n`);
  }
}

const query = process.argv[2];
if (!query) {
  console.error("Usage: npx ts-node app/main.ts <product-query>");
  process.exit(1);
}

main(query);
