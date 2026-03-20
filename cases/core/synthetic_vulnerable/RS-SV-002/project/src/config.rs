//! Agent configuration.

/// Default timeout in seconds for a single command.
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 120;

/// Runtime configuration for the build helper agent.
pub struct AgentConfig {
    /// Root directory of the project to operate on.
    pub project_root: String,
    /// Maximum number of seconds a single command may run.
    pub command_timeout_secs: u64,
}

impl AgentConfig {
    /// Create a configuration targeting the given project directory.
    pub fn from_project_path(path: &str) -> Self {
        Self {
            project_root: path.to_string(),
            command_timeout_secs: DEFAULT_COMMAND_TIMEOUT_SECS,
        }
    }
}
