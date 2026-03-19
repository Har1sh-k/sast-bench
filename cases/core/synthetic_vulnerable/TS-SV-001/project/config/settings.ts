/**
 * Coding agent configuration.
 */

export const WORKSPACE_ROOT = process.env.WORKSPACE_ROOT ?? "/workspace";

export const EXEC_TIMEOUT_MS = 30_000;

export const MAX_PLAN_STEPS = 10;

/**
 * Commands the agent is expected to run in normal operation.
 * NOTE: This allowlist exists only in config — it is never enforced
 * by the command runner.
 */
export const KNOWN_COMMANDS = [
  "npm test",
  "npm run lint",
  "npx tsc --noEmit",
  "npm run build",
];
