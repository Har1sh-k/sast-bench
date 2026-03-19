//! Agent configuration.

/// Maximum file size (in bytes) the agent will write in a single step.
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// File extensions the refactor agent is allowed to modify.
pub const ALLOWED_EXTENSIONS: &[&str] = &[".rs", ".toml", ".md", ".txt"];

/// Runtime configuration resolved from CLI arguments and environment.
pub struct Config {
    pub workspace_root: String,
    pub max_file_size: usize,
}

impl Config {
    pub fn from_workspace(root: &str) -> Self {
        Self {
            workspace_root: root.to_string(),
            max_file_size: MAX_FILE_SIZE,
        }
    }
}
