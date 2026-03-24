use std::path::Path;

use crate::agent::planner::SyncTask;

/// Dispatch a sync task to the appropriate tool.
pub fn dispatch(_workspace_root: &Path, task: &SyncTask) -> Result<String, String> {
    match task.action.as_str() {
        "copy" => Err("sync copy not yet implemented".into()),
        other => Err(format!("unknown action: {other}")),
    }
}
