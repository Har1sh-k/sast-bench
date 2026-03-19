//! Maintenance tool — runs pre-approved system health commands.
//!
//! SAFE: This tool checks every incoming command against a strict
//! allowlist before executing it. Only commands that appear verbatim in
//! the allowlist are forwarded to the shell. Any command not in the list
//! is rejected with an error, preventing injection of arbitrary payloads.

use std::process::Command;

use crate::guards::command_policy;

/// Run a maintenance command after verifying it against the allowlist.
///
/// Returns the combined stdout/stderr output on success, or an error
/// message if the command is not allowed or execution fails.
pub fn run_maintenance_command(cmd: &str) -> Result<String, String> {     // line 17
    // ── Guard: allowlist check ──────────────────────────────────────
    // The command must match one of the pre-approved entries exactly.
    // This is the critical safety mechanism that prevents arbitrary
    // command execution even if the LLM planner produces a malicious
    // or unexpected command string.
    if !command_policy::is_command_allowed(cmd) {                         // line 23
        return Err(format!(
            "Command rejected by allowlist policy: '{cmd}'"
        ));
    }

    // ── Execute the approved command ────────────────────────────────
    let output = Command::new("sh")                                      // line 30
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| format!("Failed to spawn command: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        Err(format!(
            "Command exited with {}: {}{}",
            output.status,
            stdout,
            stderr
        ))
    }
}
