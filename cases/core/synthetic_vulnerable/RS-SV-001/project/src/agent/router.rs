//! Agent router — dispatches plan steps to the appropriate tool.

use std::path::Path;

use crate::agent::planner::PlanStep;
use crate::config::{Config, ALLOWED_EXTENSIONS};
use crate::tools::file_writer::{write_file, WriteResult};

/// Check whether the relative path has an extension in the allowlist.
fn has_allowed_extension(relative_path: &str) -> bool {
    let path = Path::new(relative_path);
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => {
            let dotted = format!(".{ext}");
            ALLOWED_EXTENSIONS.contains(&dotted.as_str())
        }
        None => false,
    }
}

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

                // Enforce the configured file-size limit before writing.
                if step.content.len() > config.max_file_size {
                    results.push(WriteResult {
                        path: step.relative_path.clone(),
                        status: "error".into(),
                        message: format!(
                            "Content size ({} bytes) exceeds maximum ({} bytes)",
                            step.content.len(),
                            config.max_file_size,
                        ),
                    });
                    continue;
                }

                // Only allow writing to files with an approved extension.
                if !has_allowed_extension(&step.relative_path) {
                    results.push(WriteResult {
                        path: step.relative_path.clone(),
                        status: "error".into(),
                        message: "File extension not in allowlist".into(),
                    });
                    continue;
                }

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
