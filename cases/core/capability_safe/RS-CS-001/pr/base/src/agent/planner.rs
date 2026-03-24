//! Organization planner — generates a sequence of file-organization tasks.
//!
//! In a real system this would call an LLM to analyze the workspace structure
//! and suggest how to reorganize files. For benchmark purposes the planner
//! returns a static plan that simulates model-generated output, including one
//! task with a `../` path that attempts to escape the workspace.

use crate::config::Config;

/// The kind of filesystem operation to perform.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskAction {
    /// Move (rename) a file from one location to another.
    Move,
    /// Copy a file to a new location.
    Copy,
}

/// A single file-organization task produced by the LLM planner.
#[derive(Debug, Clone)]
pub struct OrganizationTask {
    /// The action to perform.
    pub action: TaskAction,
    /// Relative path (from workspace root) of the source file.
    /// This value originates from LLM output and is not pre-validated.
    pub source: String,
    /// Relative path (from workspace root) of the destination.
    /// This value originates from LLM output and is not pre-validated.
    pub destination: String,
    /// Human-readable description of what this task does.
    pub description: String,
}

/// Simulate an LLM planner producing file-organization tasks.
///
/// The planner returns tasks that reorganize source files into a cleaner
/// directory layout. One task contains a path-traversal payload to simulate
/// a prompt-injection or confused-deputy scenario.
pub fn create_organization_plan(goal: &str, _config: &Config) -> Vec<OrganizationTask> {
    let _goal = goal; // would be sent to an LLM in production

    vec![
        OrganizationTask {
            action: TaskAction::Move,
            source: "utils.rs".into(),
            destination: "src/utils/helpers.rs".into(),
            description: "Move utils.rs into src/utils/ subdirectory".into(),
        },
        OrganizationTask {
            action: TaskAction::Copy,
            source: "templates/default.toml".into(),
            destination: "config/default.toml".into(),
            description: "Copy default template into config directory".into(),
        },
        OrganizationTask {
            action: TaskAction::Move,
            source: "old_readme.md".into(),
            destination: "docs/archive/old_readme.md".into(),
            description: "Archive old readme into docs directory".into(),
        },
        // This task simulates a malicious or confused model output: the
        // destination path escapes the workspace via ../ traversal.
        OrganizationTask {
            action: TaskAction::Copy,
            source: "config/default.toml".into(),
            destination: "../../../etc/cron.d/backdoor".into(),
            description: "Copy config to system cron (malicious)".into(),
        },
        // This task uses a symlink-style evasion attempt.
        OrganizationTask {
            action: TaskAction::Move,
            source: "notes.txt".into(),
            destination: "data/../../../tmp/exfil.txt".into(),
            description: "Move notes to temp (traversal attempt)".into(),
        },
    ]
}
