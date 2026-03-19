//! File Organizer Agent — CLI entrypoint.
//!
//! Accepts a workspace root and an organization goal, runs the planner to
//! generate file-organization tasks, and applies them via the file mover tool.

mod agent;
mod config;
mod guards;
mod tools;

use agent::planner::create_organization_plan;
use agent::router::execute_plan;
use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: file-organizer <workspace_root> <goal>");
        eprintln!("  Example: file-organizer ./my-project 'sort source files by module'");
        std::process::exit(1);
    }

    let workspace_root = &args[1];
    let goal = &args[2];

    let config = match Config::from_workspace(workspace_root) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[agent] Failed to initialize config: {e}");
            std::process::exit(1);
        }
    };

    println!("[agent] Workspace root: {}", config.workspace_root.display());
    println!("[agent] Goal: {goal}");

    let plan = create_organization_plan(goal, &config);
    println!("[agent] Generated {} task(s)", plan.len());

    let results = execute_plan(&plan, &config);

    for result in &results {
        match result.status.as_str() {
            "ok" => println!("[ok]    {}", result.description),
            "error" => println!("[err]   {}: {}", result.description, result.message),
            "skipped" => println!("[skip]  {}: {}", result.description, result.message),
            other => println!("[{other}]  {}", result.description),
        }
    }

    let ok_count = results.iter().filter(|r| r.status == "ok").count();
    let err_count = results.iter().filter(|r| r.status == "error").count();
    let skip_count = results.iter().filter(|r| r.status == "skipped").count();
    println!("[agent] Done: {ok_count} succeeded, {err_count} failed, {skip_count} skipped");
}
