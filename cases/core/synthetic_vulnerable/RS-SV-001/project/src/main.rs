//! Workspace Refactor Agent — CLI entrypoint.
//!
//! Accepts a workspace root and a refactoring goal, runs the planner to
//! generate rewrite steps, and applies them via the file writer tool.

mod agent;
mod config;
mod tools;

use agent::planner::create_refactor_plan;
use agent::router::execute_plan;
use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: refactor-agent <workspace_root> <goal>");
        eprintln!("  Example: refactor-agent ./my-project 'rename Request to HttpRequest'");
        std::process::exit(1);
    }

    let workspace_root = &args[1];
    let goal = &args[2];

    let config = Config::from_workspace(workspace_root);

    println!("[agent] Workspace root: {}", config.workspace_root);
    println!("[agent] Goal: {goal}");

    let plan = create_refactor_plan(goal, &config);
    println!("[agent] Generated {} plan step(s)", plan.len());

    let results = execute_plan(&plan, &config);

    for result in &results {
        match result.status.as_str() {
            "ok" => println!("[ok]   {}", result.path),
            "error" => println!("[err]  {}: {}", result.path, result.message),
            other => println!("[{other}] {}", result.path),
        }
    }

    let ok_count = results.iter().filter(|r| r.status == "ok").count();
    let err_count = results.iter().filter(|r| r.status == "error").count();
    println!("[agent] Done: {ok_count} succeeded, {err_count} failed");
}
