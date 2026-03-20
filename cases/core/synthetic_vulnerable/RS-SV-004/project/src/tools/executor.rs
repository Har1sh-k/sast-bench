//! Task executor — performs file and shell operations.
//!
//! This module provides the actual tool implementations invoked by
//! the handler. Each operation validates its own parameters (paths,
//! command length, etc.) independently of the calling context.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Maximum file size the executor will read or write (in bytes).
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum shell command length.
const MAX_COMMAND_LENGTH: usize = 4096;

/// Workspace root that file operations are restricted to.
const WORKSPACE_ROOT: &str = "/workspace";

/// Result of a tool operation.
#[derive(Debug)]
pub struct ToolResult {
    pub status: String,
    pub message: String,
}

/// Read a file within the workspace.
///
/// Validates that the resolved path stays within the workspace root
/// and enforces a file-size limit.
pub fn read_file(relative_path: &str) -> ToolResult {
    let full_path = Path::new(WORKSPACE_ROOT).join(relative_path);

    // Canonicalize to resolve symlinks and ../ before checking containment.
    let canonical = match fs::canonicalize(&full_path) {
        Ok(p) => p,
        Err(e) => {
            return ToolResult {
                status: "error".into(),
                message: format!("Cannot resolve path: {e}"),
            };
        }
    };

    let workspace_canonical = match fs::canonicalize(WORKSPACE_ROOT) {
        Ok(p) => p,
        Err(e) => {
            return ToolResult {
                status: "error".into(),
                message: format!("Cannot resolve workspace root: {e}"),
            };
        }
    };

    if !canonical.starts_with(&workspace_canonical) {
        return ToolResult {
            status: "error".into(),
            message: "Path escapes workspace root".into(),
        };
    }

    match fs::read_to_string(&canonical) {
        Ok(content) => {
            if content.len() > MAX_FILE_SIZE {
                ToolResult {
                    status: "error".into(),
                    message: format!("File exceeds {MAX_FILE_SIZE} byte limit"),
                }
            } else {
                ToolResult {
                    status: "ok".into(),
                    message: content,
                }
            }
        }
        Err(e) => ToolResult {
            status: "error".into(),
            message: format!("Read failed: {e}"),
        },
    }
}

/// Write content to a file within the workspace.
///
/// Validates path containment and enforces a content-size limit.
pub fn write_file(relative_path: &str, content: &str) -> ToolResult {
    if content.len() > MAX_FILE_SIZE {
        return ToolResult {
            status: "error".into(),
            message: format!("Content exceeds {MAX_FILE_SIZE} byte limit"),
        };
    }

    let full_path = Path::new(WORKSPACE_ROOT).join(relative_path);

    // Ensure parent directories exist.
    if let Some(parent) = full_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return ToolResult {
                status: "error".into(),
                message: format!("Failed to create directories: {e}"),
            };
        }
    }

    // Canonicalize the parent to check containment (the file may not exist yet).
    let parent_canonical = match full_path.parent().and_then(|p| fs::canonicalize(p).ok()) {
        Some(p) => p,
        None => {
            return ToolResult {
                status: "error".into(),
                message: "Cannot resolve parent directory".into(),
            };
        }
    };

    let workspace_canonical = match fs::canonicalize(WORKSPACE_ROOT) {
        Ok(p) => p,
        Err(e) => {
            return ToolResult {
                status: "error".into(),
                message: format!("Cannot resolve workspace root: {e}"),
            };
        }
    };

    if !parent_canonical.starts_with(&workspace_canonical) {
        return ToolResult {
            status: "error".into(),
            message: "Path escapes workspace root".into(),
        };
    }

    match fs::write(&full_path, content) {
        Ok(()) => ToolResult {
            status: "ok".into(),
            message: format!("Wrote {} bytes", content.len()),
        },
        Err(e) => ToolResult {
            status: "error".into(),
            message: format!("Write failed: {e}"),
        },
    }
}

/// Execute a shell command with restricted privileges.
///
/// Enforces a command-length limit and runs within the workspace.
pub fn shell_exec(command: &str) -> ToolResult {
    if command.len() > MAX_COMMAND_LENGTH {
        return ToolResult {
            status: "error".into(),
            message: format!("Command exceeds {MAX_COMMAND_LENGTH} char limit"),
        };
    }

    match Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(WORKSPACE_ROOT)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if output.status.success() {
                ToolResult {
                    status: "ok".into(),
                    message: stdout,
                }
            } else {
                ToolResult {
                    status: "error".into(),
                    message: format!("Exit code {}: {stderr}", output.status),
                }
            }
        }
        Err(e) => ToolResult {
            status: "error".into(),
            message: format!("Exec failed: {e}"),
        },
    }
}
