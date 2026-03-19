/**
 * Customer Support Agent — main entrypoint.
 *
 * Accepts a support ticket ID, runs the planner to identify relevant
 * CRM / ticketing API calls, and executes them via the API client tool.
 */

import { createSupportPlan } from "../agent/planner";
import { executePlan } from "../agent/router";

async function main(ticketId: string): Promise<void> {
  console.log(`Resolving support ticket: ${ticketId}\n`);

  const plan = createSupportPlan(ticketId);
  console.log(`Generated ${plan.length} API lookup steps.\n`);

  const results = await executePlan(plan);

  for (const result of results) {
    console.log(`[${result.status}] ${result.url}`);
    console.log(`  -> ${result.summary}\n`);
  }
}

const ticketId = process.argv[2];
if (!ticketId) {
  console.error("Usage: npx ts-node app/main.ts <ticket-id>");
  process.exit(1);
}

main(ticketId);
