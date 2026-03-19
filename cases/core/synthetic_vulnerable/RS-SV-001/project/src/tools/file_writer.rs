//! File writer tool — writes refactored content to a workspace file.
//!
//! VULNERABLE: This tool joins plan-step relative paths with the workspace
//! root using `Path::join` but never canonicalizes or verifies that the
//! resolved path stays within the workspace. Paths containing `../`
//! sequences can escape to arbitrary filesystem locations.

use std::fs;
use std::path::Path;

/// Result of a single file-write operation.
#[derive(Debug)]
pub struct WriteResult {
    pub path: String,
    pub status: String,
    pub message: String,
}

/// Write refactored content to `relative_path` under `workspace_root`.
///
/// The `relative_path` originates from the LLM planner output and may
/// contain arbitrary path components. This function uses `Path::join` to
/// combine the workspace root with the relative path, but `Path::join`
/// does not neutralize `..` segments.
///
/// A safe implementation would call `std::fs::canonicalize()` on the
/// joined path and verify that it `starts_with()` the canonicalized
/// workspace root before writing. That check is missing here.
pub fn write_file(
    workspace_root: &str,
    relative_path: &str,
    content: &str,
) -> WriteResult {
    // Join the workspace root with the plan-step path. Path::join does
    // NOT resolve `..` components — the resulting path can point outside
    // the workspace.
    let full_path = Path::new(workspace_root).join(relative_path);

    // Create parent directories so nested module paths work.
    if let Some(parent) = full_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return WriteResult {
                path: relative_path.to_string(),
                status: "error".into(),
                message: format!("Failed to create directories: {e}"),
            };
        }
    }

    // Write the refactored content. This is the vulnerable sink — the
    // path may resolve outside the workspace root.
    match fs::write(&full_path, content) {
        Ok(()) => WriteResult {
            path: relative_path.to_string(),
            status: "ok".into(),
            message: String::new(),
        },
        Err(e) => WriteResult {
            path: relative_path.to_string(),
            status: "error".into(),
            message: format!("Write failed: {e}"),
        },
    }
}
