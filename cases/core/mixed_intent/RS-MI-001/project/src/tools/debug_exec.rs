//! Debug execution tool — runs arbitrary diagnostic commands.
//!
//! VULNERABLE: This tool accepts a command string from the agent planner
//! and passes it directly to a shell without any validation, sanitization,
//! or allowlist check. If the LLM planner produces a malicious command
//! (via prompt injection, hallucination, or confused-deputy attack), it
//! will be executed with the full privileges of the host process.

use std::process::Command;

/// Run an arbitrary debug command without any validation.
///
/// The `cmd` parameter originates from the LLM planner and may contain
/// any shell expression. This function forwards it verbatim to
/// `sh -c <cmd>`, making it a command injection sink.
///
/// A safe implementation would either:
/// - Apply the same allowlist policy used by the maintenance tool, or
/// - Restrict debug commands to a sandboxed environment, or
/// - Require explicit user confirmation before execution.
///
/// None of those guards are present here.
pub fn run_debug_command(cmd: &str) -> Result<String, String> {           // line 23
    // No validation, no allowlist check, no sandboxing.
    // The command is passed straight to the shell.
    let output = Command::new("sh")                                       // line 26
        .arg("-c")
        .arg(cmd)                                                         // line 28
        .output()
        .map_err(|e| format!("Failed to spawn debug command: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        // Even on failure, return the output for diagnostic purposes.
        Ok(format!(
            "[exit {}] {}{}",
            output.status,
            stdout,
            stderr
        ))
    }
}
