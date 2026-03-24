//! Path guard — validates that paths resolve inside the workspace root.
//!
//! Uses `std::fs::canonicalize` to resolve symlinks and `..` sequences,
//! then checks containment.  The validated path is returned for later use.

use std::fs;
use std::path::{Path, PathBuf};

/// Validate that `path` resolves within `workspace_root` after
/// canonicalization.  Returns the canonicalized path on success.
///
/// VULNERABILITY: This function returns the canonicalized path but the
/// caller uses it in a separate filesystem operation later.  Between
/// this check and actual use, an attacker can swap a symlink at the
/// original path to point outside the workspace (TOCTOU race).
pub fn validate_path(workspace_root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canon_root = fs::canonicalize(workspace_root)
        .map_err(|e| format!("cannot canonicalize workspace root: {e}"))?;

    let canon_path = fs::canonicalize(path)
        .map_err(|e| format!("cannot canonicalize '{}': {e}", path.display()))?;

    if !canon_path.starts_with(&canon_root) {
        return Err(format!(
            "path '{}' resolves outside workspace '{}'",
            canon_path.display(),
            canon_root.display(),
        ));
    }

    // Returns the canonicalized path, but the underlying filesystem entry
    // can change before the caller acts on this result.
    Ok(canon_path)
}
