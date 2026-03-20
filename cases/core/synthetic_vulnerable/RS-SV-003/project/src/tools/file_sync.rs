//! File sync tool — copies files within the workspace for backup.
//!
//! The tool validates source and destination paths against the workspace root
//! using `path_guard::validate_path`, which canonicalizes and checks
//! containment.  However, the validated (canonicalized) path is used in a
//! *separate* `fs::copy` call after the check.  Between validation and use,
//! an attacker can replace the source with a symlink to an arbitrary file
//! outside the workspace (TOCTOU race condition).
//!
//! Missing guard: the tool should re-canonicalize the source path immediately
//! before the copy, or open the file with O_NOFOLLOW and verify the fd.

use std::fs;
use std::path::Path;

use crate::guards::path_guard;

/// Copy `source` to `destination`, both relative to `workspace_root`.
///
/// Both paths are validated against the workspace boundary before the copy.
/// However, the gap between validation and `fs::copy` is exploitable via
/// symlink swap (TOCTOU).
pub fn sync_copy(
    workspace_root: &Path,
    source: &str,
    destination: &str,
) -> Result<String, String> {
    let abs_source = workspace_root.join(source);
    let abs_dest = workspace_root.join(destination);

    // Step 1: Validate source is inside the workspace.
    let validated_source = path_guard::validate_path(workspace_root, &abs_source)
        .map_err(|e| format!("source rejected: {e}"))?;

    // Step 2: Validate destination is inside the workspace.
    let validated_dest = path_guard::validate_path(workspace_root, &abs_dest)
        .map_err(|e| format!("destination rejected: {e}"))?;

    // Ensure the destination parent directory exists.
    if let Some(parent) = validated_dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory: {e}"))?;
    }

    // Step 3: Perform the copy using the previously validated paths.
    //
    // VULNERABLE: Between step 1 and this point, the symlink at
    // `abs_source` can be swapped to point to /etc/shadow, ~/.ssh/id_rsa,
    // or any other file.  `validated_source` still holds the old
    // canonicalized path, but `fs::copy` follows the *current* filesystem
    // state of `abs_source` — not the snapshot from step 1.
    //
    // On most platforms, fs::copy resolves the source path again internally,
    // so swapping the symlink between validate_path and fs::copy causes the
    // copy to read from the attacker-controlled target.
    fs::copy(&abs_source, &validated_dest).map_err(|e| {
        format!(
            "copy failed: {e} (from {} to {})",
            validated_source.display(),
            validated_dest.display(),
        )
    })?;

    Ok(format!(
        "synced {} -> {}",
        validated_source.display(),
        validated_dest.display(),
    ))
}
