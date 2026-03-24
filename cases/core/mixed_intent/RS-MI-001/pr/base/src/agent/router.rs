//! Agent router — dispatches tasks to the appropriate tool.

use crate::agent::planner::{Task, TaskAction};
use crate::config::Config;
use crate::tools::maintenance;

/// The outcome of executing a single task.
#[derive(Debug)]
pub struct TaskResult {
    pub task_label: String,
    pub success: bool,
    pub summary: String,
}

/// Execute every task in the plan and collect results.
pub fn execute_plan(plan: &[Task], config: &Config) -> Vec<TaskResult> {
    let mut results = Vec::new();

    for task in plan {
        let result = match task.action {
            TaskAction::Maintenance => {
                println!(
                    "[router] maintenance: {} — '{}'",
                    task.label, task.command
                );
                let output = maintenance::run_maintenance_command(&task.command);
                match output {
                    Ok(out) => TaskResult {
                        task_label: task.label.clone(),
                        success: true,
                        summary: truncate(&out, config.max_output_len),
                    },
                    Err(e) => TaskResult {
                        task_label: task.label.clone(),
                        success: false,
                        summary: e,
                    },
                }
            }
            TaskAction::DebugExec => {
                println!(
                    "[router] debug_exec: {} — '{}' (unsupported)",
                    task.label, task.command
                );
                TaskResult {
                    task_label: task.label.clone(),
                    success: false,
                    summary: "Debug execution is not supported in this build".to_string(),
                }
            }
        };

        results.push(result);
    }

    results
}

/// Truncate a string to at most `max_len` bytes, appending "..." if trimmed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
