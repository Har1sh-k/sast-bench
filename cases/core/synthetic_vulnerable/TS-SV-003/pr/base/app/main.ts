/**
 * Plugin Agent — CLI entrypoint.
 *
 * Standalone version without plugin loading support.
 */

import { REGISTRY_URL } from "../config/settings";

async function main(): Promise<void> {
  console.log(`Agent starting, registry: ${REGISTRY_URL}\n`);

  console.log("No plugins loaded (plugin system not available).");
  console.log("\nSummary: 0 loaded, 0 failed");
}

main().catch((err) => {
  console.error("Agent crashed:", err);
  process.exit(1);
});
