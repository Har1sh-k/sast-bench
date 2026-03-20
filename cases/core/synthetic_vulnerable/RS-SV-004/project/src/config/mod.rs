//! Orchestrator configuration.

/// Maximum payload size the handler will accept (in bytes).
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB

/// Allowed command types for peer agents.
/// NOTE: This list exists for documentation — the handler does not enforce it.
pub const KNOWN_COMMANDS: &[&str] = &["read_file", "write_file", "shell_exec"];

/// Expected authentication header name.
/// NOTE: This constant is defined but never checked by the handler.
pub const AUTH_HEADER: &str = "X-Agent-Token";

/// Runtime configuration resolved from CLI arguments.
pub struct Config {
    pub bind_address: String,
}

impl Config {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            bind_address: bind_addr.to_string(),
        }
    }
}
