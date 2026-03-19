//! Agent configuration.

use std::fs;
use std::path::PathBuf;

/// Maximum total bytes the agent will move or copy in a single run.
pub const MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024; // 50 MB

/// Runtime configuration resolved from CLI arguments.
pub struct Config {
    /// Canonicalized workspace root directory.
    pub workspace_root: PathBuf,
    /// Cumulative byte budget for the entire run.
    pub max_total_bytes: u64,
}

impl Config {
    /// Create a configuration from a workspace root path.
    ///
    /// The workspace root is immediately canonicalized so that all subsequent
    /// path checks use a consistent, absolute reference point.
    pub fn from_workspace(root: &str) -> Result<Self, String> {
        let workspace_root = fs::canonicalize(root)
            .map_err(|e| format!("invalid workspace root '{}': {e}", root))?;

        if !workspace_root.is_dir() {
            return Err(format!(
                "workspace root is not a directory: {}",
                workspace_root.display()
            ));
        }

        Ok(Self {
            workspace_root,
            max_total_bytes: MAX_TOTAL_BYTES,
        })
    }
}
