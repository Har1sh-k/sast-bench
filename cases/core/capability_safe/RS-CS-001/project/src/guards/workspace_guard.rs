//! Workspace root guard — ensures all file paths resolve within the workspace.
//!
//! This module provides the core security invariant for the file organizer
//! agent: no filesystem operation may target a path outside the canonicalized
//! workspace root. It handles both existing paths (via `std::fs::canonicalize`)
//! and not-yet-existing paths (by canonicalizing the nearest existing ancestor
//! and re-appending the remaining components).

use std::fs;
use std::path::{Path, PathBuf};

/// Validate that an existing path, after canonicalization, resides within the
/// workspace root. Returns the canonicalized path on success.
///
/// # Errors
///
/// Returns an error string if:
/// - The path cannot be canonicalized (e.g., does not exist).
/// - The canonicalized path is not a descendant of the workspace root.
pub fn validate_existing_path(workspace_root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canon_root = fs::canonicalize(workspace_root)
        .map_err(|e| format!("cannot canonicalize workspace root: {e}"))?;

    let canon_path = fs::canonicalize(path)
        .map_err(|e| format!("cannot canonicalize path '{}': {e}", path.display()))?;

    if !canon_path.starts_with(&canon_root) {
        return Err(format!(
            "path '{}' resolves outside workspace root '{}'",
            canon_path.display(),
            canon_root.display()
        ));
    }

    Ok(canon_path)
}

/// Validate that a potentially non-existent path, after canonicalization of
/// its nearest existing ancestor, resides within the workspace root. Returns
/// the resolved absolute path on success.
///
/// This is necessary for destination paths that have not been created yet.
/// We walk up the path components until we find an existing ancestor, canonicalize
/// that ancestor, then re-append the remaining components and normalize.
///
/// # Errors
///
/// Returns an error string if:
/// - No existing ancestor can be found or canonicalized.
/// - The resolved path is not a descendant of the workspace root.
pub fn validate_new_path(workspace_root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canon_root = fs::canonicalize(workspace_root)
        .map_err(|e| format!("cannot canonicalize workspace root: {e}"))?;

    // Collect trailing components that don't exist yet.
    let mut trailing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut ancestor = path.to_path_buf();

    loop {
        match fs::canonicalize(&ancestor) {
            Ok(canon_ancestor) => {
                // Rebuild the full path from the canonicalized ancestor.
                let mut resolved = canon_ancestor;
                for component in trailing.iter().rev() {
                    resolved.push(component);
                }

                // Normalize away any remaining `.` or `..` in the trailing
                // portion. We cannot use `canonicalize` because the full path
                // does not exist yet, so we use a component-by-component
                // normalization.
                let resolved = normalize_path(&resolved);

                if !resolved.starts_with(&canon_root) {
                    return Err(format!(
                        "path '{}' resolves outside workspace root '{}'",
                        resolved.display(),
                        canon_root.display()
                    ));
                }

                return Ok(resolved);
            }
            Err(_) => {
                // This ancestor does not exist; move one level up.
                match ancestor.file_name() {
                    Some(name) => {
                        trailing.push(name);
                        ancestor = ancestor
                            .parent()
                            .ok_or_else(|| {
                                format!(
                                    "no existing ancestor found for path '{}'",
                                    path.display()
                                )
                            })?
                            .to_path_buf();
                    }
                    None => {
                        return Err(format!(
                            "cannot resolve path '{}': no existing ancestor",
                            path.display()
                        ));
                    }
                }
            }
        }
    }
}

/// Re-canonicalize a path immediately before use and verify it still resolves
/// within the workspace root.  This closes the TOCTOU window between an
/// earlier `validate_*` call and the actual filesystem operation: if a symlink
/// was swapped between validation and use, the second canonicalization will
/// catch the change.
///
/// # Errors
///
/// Returns an error if the path no longer exists, cannot be canonicalized, or
/// now resolves outside the workspace root.
pub fn revalidate_at_use(workspace_root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canon_root = fs::canonicalize(workspace_root)
        .map_err(|e| format!("cannot canonicalize workspace root: {e}"))?;

    let canon_now = fs::canonicalize(path)
        .map_err(|e| format!("re-canonicalization failed for '{}': {e}", path.display()))?;

    if !canon_now.starts_with(&canon_root) {
        return Err(format!(
            "TOCTOU check failed: '{}' now resolves outside workspace root '{}'",
            canon_now.display(),
            canon_root.display()
        ));
    }

    Ok(canon_now)
}

/// Normalize a path by resolving `.` and `..` components lexically.
/// Unlike `canonicalize`, this does not require the path to exist.
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Only pop if there is a normal component to remove.
                // Never pop past the root.
                if matches!(components.last(), Some(std::path::Component::Normal(_))) {
                    components.pop();
                } else {
                    components.push(component);
                }
            }
            std::path::Component::CurDir => {
                // Skip `.` components.
            }
            _ => {
                components.push(component);
            }
        }
    }

    components.iter().collect()
}
