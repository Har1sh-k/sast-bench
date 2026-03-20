use std::path::Path;

use crate::agent::planner::SyncTask;
use crate::tools::file_sync;

/// Dispatch a sync task to the appropriate tool.
pub fn dispatch(workspace_root: &Path, task: &SyncTask) -> Result<String, String> {
    match task.action.as_str() {
        "copy" => file_sync::sync_copy(workspace_root, &task.source, &task.destination),
        other => Err(format!("unknown action: {other}")),
    }
}
