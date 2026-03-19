/**
 * Command runner tool — executes shell commands on behalf of the agent.
 *
 * VULNERABLE: This tool receives shell fragments directly from the agent
 * planner (which are ultimately model-generated) and passes them to
 * child_process.exec() without validating them against a command
 * allowlist. A compromised or prompt-injected model can therefore
 * execute arbitrary commands on the host.
 */

import { exec } from "child_process";
import { EXEC_TIMEOUT_MS, WORKSPACE_ROOT } from "../config/settings";

export interface CommandResult {
  status: "ok" | "error";
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export function runCommand(command: string): Promise<CommandResult> {   // line 21
  /**
   * Execute a shell command and return its output.
   *
   * `command` originates from the agent planner, whose output is
   * controlled by the language model. There is no validation that
   * the command matches a known-safe set (e.g. the KNOWN_COMMANDS
   * allowlist defined in config/settings.ts).
   *
   * Enforcing an allowlist — or at minimum using execFile() with an
   * explicit argv array instead of exec() — would prevent arbitrary
   * command execution here but is missing.
   */
  return new Promise((resolve) => {
    exec(                                                              // line 35
      command,
      {
        cwd: WORKSPACE_ROOT,
        timeout: EXEC_TIMEOUT_MS,
        shell: "/bin/sh",
      },
      (error, stdout, stderr) => {
        resolve({
          status: error ? "error" : "ok",
          command,
          stdout: stdout.toString(),
          stderr: stderr.toString(),
          exitCode: error?.code ?? 0,
        });
      },
    );                                                                 // line 48
  });
}
