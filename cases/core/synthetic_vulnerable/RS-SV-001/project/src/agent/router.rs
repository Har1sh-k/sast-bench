//! Agent router — dispatches plan steps to the appropriate tool.

use crate::agent::planner::PlanStep;
use crate::config::Config;
use crate::tools::file_writer::{write_file, WriteResult};

/// Execute every step in the refactoring plan and collect results.
pub fn execute_plan(plan: &[PlanStep], config: &Config) -> Vec<WriteResult> {
    let mut results = Vec::new();

    for step in plan {
        match step.action.as_str() {
            "rewrite_file" => {
                println!(
                    "[router] rewrite_file: {} — {}",
                    step.relative_path, step.description
                );
                let result = write_file(
                    &config.workspace_root,
                    &step.relative_path,
                    &step.content,
                );
                results.push(result);
            }
            other => {
                eprintln!("[router] Unknown action: {other}, skipping");
                results.push(WriteResult {
                    path: step.relative_path.clone(),
                    status: "skipped".into(),
                    message: format!("Unknown action: {other}"),
                });
            }
        }
    }

    results
}
