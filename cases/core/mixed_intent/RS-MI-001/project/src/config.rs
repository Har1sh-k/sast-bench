//! Agent configuration.

/// Maximum output length (in bytes) to capture from any single command.
pub const MAX_OUTPUT_LEN: usize = 64 * 1024; // 64 KB

/// Timeout in seconds for individual command execution.
pub const COMMAND_TIMEOUT_SECS: u64 = 30;

/// Runtime configuration resolved from environment and defaults.
pub struct Config {
    pub hostname: String,
    pub max_output_len: usize,
    pub command_timeout_secs: u64,
    pub debug_enabled: bool,
}

impl Config {
    pub fn load() -> Self {
        let hostname = std::env::var("OPS_HOSTNAME")
            .unwrap_or_else(|_| "localhost".to_string());
        let debug_enabled = std::env::var("OPS_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            hostname,
            max_output_len: MAX_OUTPUT_LEN,
            command_timeout_secs: COMMAND_TIMEOUT_SECS,
            debug_enabled,
        }
    }
}
