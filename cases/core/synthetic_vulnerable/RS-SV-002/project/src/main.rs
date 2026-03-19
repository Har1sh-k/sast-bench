//! Build Helper Agent — CLI entrypoint.
//!
//! Accepts a project path, runs the planner to produce build/test tasks,
//! and dispatches them through the agent router.

mod agent;
mod config;
mod tools;

use agent::planner::create_build_plan;
use agent::router::execute_plan;
use config::AgentConfig;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: build-helper-agent <project_path>");
        std::process::exit(1);
    }

    let project_path = &args[1];
    let config = AgentConfig::default();

    println!("[agent] Planning build tasks for: {}", project_path);
    let plan = create_build_plan(project_path);

    println!("[agent] Executing {} task(s)...", plan.len());
    let results = execute_plan(&plan, &config);

    for result in &results {
        let status = if result.success { "OK" } else { "FAIL" };
        println!("[{}] {}: {}", status, result.task_action, result.output);
    }

    let failures = results.iter().filter(|r| !r.success).count();
    if failures > 0 {
        eprintln!("[agent] {} task(s) failed.", failures);
        std::process::exit(1);
    }

    println!("[agent] All tasks completed successfully.");
}
