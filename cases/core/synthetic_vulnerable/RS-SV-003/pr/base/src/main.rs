mod agent;
mod guards;
mod tools;

fn main() {
    let workspace = std::env::var("AGENT_WORKSPACE")
        .unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&workspace);

    // Simulate an LLM planner producing sync tasks.
    let tasks = agent::planner::build_sync_plan();

    println!("File-sync agent starting (workspace: {})", workspace_root.display());

    for task in &tasks {
        match agent::router::dispatch(workspace_root, task) {
            Ok(msg) => println!("  OK: {msg}"),
            Err(err) => eprintln!("  REJECTED: {err}"),
        }
    }
}
