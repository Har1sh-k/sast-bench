//! Agent router — dispatches organization tasks to the appropriate tool.
//!
//! This is the base version before the file mover tool was implemented.
//! All actions are skipped because no tool is available to handle them.

use crate::agent::planner::OrganizationTask;
use crate::config::Config;

/// Result of executing a single organization task.
#[derive(Debug)]
pub struct TaskResult {
    pub description: String,
    pub status: String,
    pub message: String,
}

/// Execute every task in the organization plan and collect results.
///
/// No file-operation tool is available yet, so every task is skipped.
pub fn execute_plan(plan: &[OrganizationTask], _config: &Config) -> Vec<TaskResult> {
    let mut results = Vec::new();

    for task in plan {
        println!(
            "[router] {:?}: {} -> {} — {}",
            task.action, task.source, task.destination, task.description
        );

        let result = TaskResult {
            description: task.description.clone(),
            status: "skipped".into(),
            message: "no tool available to handle this action".into(),
        };

        results.push(result);
    }

    results
}
