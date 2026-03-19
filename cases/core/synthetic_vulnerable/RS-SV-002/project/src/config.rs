//! Agent configuration.

/// Runtime configuration for the build helper agent.
pub struct AgentConfig {
    /// Root directory of the project to operate on.
    pub project_root: String,
    /// Maximum number of seconds a single command may run.
    pub command_timeout_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            project_root: ".".into(),
            command_timeout_secs: 120,
        }
    }
}
