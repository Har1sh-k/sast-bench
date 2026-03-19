/**
 * Travel Planning Agent — main entrypoint.
 *
 * Accepts a destination query, runs the planner to identify travel-related
 * URLs, and fetches them via the URL fetcher tool.
 */

import { createTravelPlan } from "../agent/planner";
import { executePlan } from "../agent/router";

async function main(destination: string): Promise<void> {
  console.log(`Planning trip to: ${destination}\n`);

  const plan = createTravelPlan(destination);
  console.log(`Generated ${plan.length} research steps.\n`);

  const results = await executePlan(plan);

  for (const result of results) {
    console.log(`[${result.status}] ${result.url}: ${result.title}`);
  }
}

const destination = process.argv[2];
if (!destination) {
  console.error("Usage: npx ts-node app/main.ts <destination>");
  process.exit(1);
}

main(destination);
