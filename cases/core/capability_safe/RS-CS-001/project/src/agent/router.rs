//! Agent router — dispatches organization tasks to the appropriate tool.

use crate::agent::planner::{OrganizationTask, TaskAction};
use crate::config::Config;
use crate::tools::file_mover;

/// Result of executing a single organization task.
#[derive(Debug)]
pub struct TaskResult {
    pub description: String,
    pub status: String,
    pub message: String,
}

/// Execute every task in the organization plan and collect results.
pub fn execute_plan(plan: &[OrganizationTask], config: &Config) -> Vec<TaskResult> {
    let mut results = Vec::new();

    for task in plan {
        println!(
            "[router] {:?}: {} -> {} — {}",
            task.action, task.source, task.destination, task.description
        );

        let outcome = match task.action {
            TaskAction::Move => {
                file_mover::move_file(&config.workspace_root, &task.source, &task.destination)
            }
            TaskAction::Copy => {
                file_mover::copy_file(&config.workspace_root, &task.source, &task.destination)
            }
        };

        let result = match outcome {
            Ok(msg) => TaskResult {
                description: task.description.clone(),
                status: "ok".into(),
                message: msg,
            },
            Err(e) => TaskResult {
                description: task.description.clone(),
                status: "error".into(),
                message: e,
            },
        };

        results.push(result);
    }

    results
}
