/// Task produced by the LLM planner for the file-sync agent.
pub struct SyncTask {
    pub action: String,
    pub source: String,
    pub destination: String,
}

/// Simulate an LLM planner producing a list of file-sync tasks.
/// In a real agent, these would come from model output.
pub fn build_sync_plan() -> Vec<SyncTask> {
    vec![
        SyncTask {
            action: "copy".into(),
            source: "data/report.txt".into(),
            destination: "backup/report.txt".into(),
        },
        SyncTask {
            action: "copy".into(),
            source: "data/metrics.json".into(),
            destination: "backup/metrics.json".into(),
        },
    ]
}
