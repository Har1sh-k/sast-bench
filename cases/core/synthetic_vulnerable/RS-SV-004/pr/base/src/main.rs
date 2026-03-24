//! Multi-Agent Orchestrator — CLI entrypoint.
//!
//! Starts the coordinator agent HTTP server that listens for task
//! commands from peer agents and dispatches them to internal tools.

mod config;

use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: orchestrator <bind_address>");
        eprintln!("  Example: orchestrator 0.0.0.0:8080");
        std::process::exit(1);
    }

    let bind_addr = &args[1];
    let config = Config::new(bind_addr);

    println!("[orchestrator] Binding to {}", config.bind_address);
    println!("[orchestrator] TODO: agent handler and tool executor not yet implemented");
}
