//! Local Ops Assistant — CLI entrypoint.
//!
//! Accepts an operation mode and optional arguments, runs the planner to
//! generate a task list, and dispatches each task to the appropriate tool.

mod agent;
mod config;
mod guards;
mod tools;

use agent::planner::create_ops_plan;
use agent::router::execute_plan;
use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ops-assistant <mode> [extra_args...]");
        eprintln!("  Modes: routine-check, debug-session");
        eprintln!("  Example: ops-assistant routine-check");
        eprintln!("  Example: ops-assistant debug-session 'ls -la /tmp'");
        std::process::exit(1);
    }

    let mode = &args[1];
    let extra: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    let config = Config::load();

    println!("[agent] Mode: {mode}");
    println!("[agent] Host: {}", config.hostname);

    let plan = create_ops_plan(mode, &extra, &config);
    println!("[agent] Generated {} task(s)", plan.len());

    let results = execute_plan(&plan, &config);

    for result in &results {
        match result.success {
            true => println!("[ok]   {}: {}", result.task_label, result.summary),
            false => println!("[err]  {}: {}", result.task_label, result.summary),
        }
    }

    let ok_count = results.iter().filter(|r| r.success).count();
    let err_count = results.iter().filter(|r| !r.success).count();
    println!("[agent] Done: {ok_count} succeeded, {err_count} failed");
}
