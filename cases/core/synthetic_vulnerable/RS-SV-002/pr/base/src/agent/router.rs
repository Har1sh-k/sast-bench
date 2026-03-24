//! Agent router — dispatches build tasks to the appropriate tool.

use crate::agent::planner::BuildTask;
use crate::config::AgentConfig;

/// Result of executing a single build task.
#[derive(Debug)]
pub struct TaskResult {
    pub task_action: String,
    pub success: bool,
    pub output: String,
}

/// Execute each task in the build plan and collect results.
///
/// Build tool execution is not yet implemented; all tasks return an error.
pub fn execute_plan(plan: &[BuildTask], _config: &AgentConfig) -> Vec<TaskResult> {
    let mut results = Vec::new();

    for task in plan {
        let result = TaskResult {
            task_action: task.action.clone(),
            success: false,
            output: format!("Action '{}' is not yet implemented", task.action),
        };
        results.push(result);
    }

    results
}
