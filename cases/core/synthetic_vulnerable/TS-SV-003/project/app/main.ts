/**
 * Plugin Agent — CLI entrypoint.
 *
 * Starts the agent, loads plugins from the configured registry,
 * and reports the results.
 */

import { loadAllPlugins, LoadedPlugin } from "../agent/plugin-loader";
import { REGISTRY_URL } from "../config/settings";

function printResults(results: LoadedPlugin[]): void {
  for (const { name, version, status, message } of results) {
    const tag = status === "ok" ? "LOADED" : "FAILED";
    console.log(`[${tag}] ${name}@${version}: ${message}`);
  }
}

async function main(): Promise<void> {
  console.log(`Agent starting, registry: ${REGISTRY_URL}\n`);

  const results = await loadAllPlugins();

  console.log(`\nLoaded ${results.length} plugin(s):\n`);
  printResults(results);

  const ok = results.filter((r) => r.status === "ok").length;
  const failed = results.filter((r) => r.status === "error").length;
  console.log(`\nSummary: ${ok} loaded, ${failed} failed`);
}

main().catch((err) => {
  console.error("Agent crashed:", err);
  process.exit(1);
});
