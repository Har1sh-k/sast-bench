//! Agent router — dispatches build tasks to the appropriate tool.

use crate::agent::planner::BuildTask;
use crate::config::AgentConfig;
use crate::tools::build_runner;

/// Result of executing a single build task.
#[derive(Debug)]
pub struct TaskResult {
    pub task_action: String,
    pub success: bool,
    pub output: String,
}

/// Execute each task in the build plan and collect results.
pub fn execute_plan(plan: &[BuildTask], config: &AgentConfig) -> Vec<TaskResult> {
    let mut results = Vec::new();

    for task in plan {
        let result = match task.action.as_str() {
            "build" => build_runner::run_build(task, config),
            "test" => build_runner::run_tests(task, config),
            "lint" => build_runner::run_lint(task, config),
            other => TaskResult {
                task_action: other.to_string(),
                success: false,
                output: format!("Unknown action: {}", other),
            },
        };
        results.push(result);
    }

    results
}
