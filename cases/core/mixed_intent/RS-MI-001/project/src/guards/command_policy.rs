//! Command allowlist policy.
//!
//! Defines the set of shell commands that the maintenance tool is
//! permitted to execute. Any command not present in this list is
//! rejected before it reaches a shell.

/// Hardcoded allowlist of maintenance commands. Each entry is the exact
/// command string that may be passed to the shell. The maintenance tool
/// must check incoming commands against this list before execution.
pub const ALLOWED_COMMANDS: &[&str] = &[
    "df -h",
    "uptime",
    "free -m",
    "systemctl status nginx",
    "systemctl status postgresql",
    "journalctl -u nginx --no-pager -n 50",
    "journalctl -u postgresql --no-pager -n 50",
    "ps aux --sort=-%mem | head -20",
    "du -sh /var/log",
    "cat /proc/loadavg",
];

/// Check whether `cmd` is present in the maintenance command allowlist.
///
/// The comparison is exact (byte-for-byte) — no shell expansion, glob
/// matching, or prefix matching is performed. This ensures that only
/// the precise pre-approved commands can be executed.
pub fn is_command_allowed(cmd: &str) -> bool {
    ALLOWED_COMMANDS.contains(&cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_commands_pass() {
        assert!(is_command_allowed("df -h"));
        assert!(is_command_allowed("uptime"));
        assert!(is_command_allowed("systemctl status nginx"));
    }

    #[test]
    fn disallowed_commands_rejected() {
        assert!(!is_command_allowed("rm -rf /"));
        assert!(!is_command_allowed("curl http://evil.example.com"));
        assert!(!is_command_allowed("df -h; cat /etc/passwd"));
        assert!(!is_command_allowed(""));
    }

    #[test]
    fn partial_match_rejected() {
        // "df -h" is allowed but "df -ha" is not.
        assert!(!is_command_allowed("df -ha"));
        // Leading/trailing whitespace should not match.
        assert!(!is_command_allowed(" df -h"));
        assert!(!is_command_allowed("df -h "));
    }
}
