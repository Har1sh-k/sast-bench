//! File mover tool — moves and copies files within the workspace.
//!
//! Every operation validates that both source and destination paths resolve
//! inside the workspace root by canonicalizing paths and checking containment.
//! This prevents path-traversal attacks from LLM-generated task parameters.

use std::fs;
use std::path::Path;

use crate::guards::workspace_guard;

/// File extensions that the organizer is allowed to operate on.
const ALLOWED_EXTENSIONS: &[&str] = &[
    "rs", "toml", "md", "txt", "json", "yaml", "yml", "lock", "cfg",
];

/// Check whether the file extension is in the allowlist.
fn has_allowed_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ALLOWED_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
}

/// Move (rename) a file from `source` to `destination`, both relative to the
/// workspace root. Returns `Ok` with a summary or `Err` with a reason.
///
/// SAFETY: Both paths are canonicalized and checked against the workspace root
/// before any filesystem mutation occurs.
pub fn move_file(
    workspace_root: &Path,
    source: &str,
    destination: &str,
) -> Result<String, String> {
    let abs_source = workspace_root.join(source);
    let abs_dest = workspace_root.join(destination);

    // Validate the source path is inside the workspace.
    let canon_source = workspace_guard::validate_existing_path(workspace_root, &abs_source)
        .map_err(|e| format!("source rejected: {e}"))?;

    // Validate the destination path is inside the workspace.
    // The destination may not exist yet, so we canonicalize its parent.
    let canon_dest = workspace_guard::validate_new_path(workspace_root, &abs_dest)
        .map_err(|e| format!("destination rejected: {e}"))?;

    if !has_allowed_extension(&canon_source) {
        return Err(format!(
            "source file extension not in allowlist: {}",
            canon_source.display()
        ));
    }

    // Ensure the destination directory exists.
    if let Some(parent) = canon_dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create destination directory: {e}"))?;
    }

    fs::rename(&canon_source, &canon_dest).map_err(|e| {
        format!(
            "rename failed: {e} (from {} to {})",
            canon_source.display(),
            canon_dest.display()
        )
    })?;

    Ok(format!(
        "moved {} -> {}",
        canon_source.display(),
        canon_dest.display()
    ))
}

/// Copy a file from `source` to `destination`, both relative to the workspace
/// root. Returns `Ok` with a summary or `Err` with a reason.
///
/// SAFETY: Both paths are canonicalized and checked against the workspace root
/// before any filesystem mutation occurs.
pub fn copy_file(
    workspace_root: &Path,
    source: &str,
    destination: &str,
) -> Result<String, String> {
    let abs_source = workspace_root.join(source);
    let abs_dest = workspace_root.join(destination);

    // Validate the source path is inside the workspace.
    let canon_source = workspace_guard::validate_existing_path(workspace_root, &abs_source)
        .map_err(|e| format!("source rejected: {e}"))?;

    // Validate the destination path is inside the workspace.
    let canon_dest = workspace_guard::validate_new_path(workspace_root, &abs_dest)
        .map_err(|e| format!("destination rejected: {e}"))?;

    if !has_allowed_extension(&canon_source) {
        return Err(format!(
            "source file extension not in allowlist: {}",
            canon_source.display()
        ));
    }

    // Ensure the destination directory exists.
    if let Some(parent) = canon_dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create destination directory: {e}"))?;
    }

    fs::copy(&canon_source, &canon_dest).map_err(|e| {
        format!(
            "copy failed: {e} (from {} to {})",
            canon_source.display(),
            canon_dest.display()
        )
    })?;

    Ok(format!(
        "copied {} -> {}",
        canon_source.display(),
        canon_dest.display()
    ))
}
