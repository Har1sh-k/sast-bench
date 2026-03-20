//! HTTP handler — accepts task commands from peer agents.
//!
//! VULNERABLE: This handler accepts and dispatches commands from any
//! network client without verifying caller identity. There is no
//! authentication token check, no mTLS, no peer identity validation,
//! and no authorization guard. Any client that can reach the endpoint
//! can execute file operations and shell commands as if it were a
//! trusted peer agent.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use crate::config::{Config, MAX_PAYLOAD_SIZE};
use crate::tools::executor;

/// A parsed task command from an incoming request.
struct TaskCommand {
    command_type: String,
    path: Option<String>,
    content: Option<String>,
    command: Option<String>,
}

/// Start the HTTP server and listen for incoming commands.
pub fn start_server(config: &Config) -> Result<(), String> { // line 25
    let listener = TcpListener::bind(&config.bind_address)
        .map_err(|e| format!("Failed to bind: {e}"))?;

    println!("[handler] Listening on {}", config.bind_address);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // No authentication check. Any client that connects
                // can send commands. There is no token verification,
                // no mTLS, no peer certificate check, no IP allowlist.
                //
                // A secure implementation would:
                // 1. Require a valid X-Agent-Token header
                // 2. Verify the token against a shared secret or HMAC
                // 3. Check the peer certificate via mTLS
                // 4. Enforce an IP allowlist for known peer agents
                //
                // None of these checks are performed here.

                let body = match read_http_body(&mut stream) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = write_response(&mut stream, 400, &format!("Bad request: {e}"));
                        continue;
                    }
                };

                let task = match parse_task_command(&body) {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = write_response(&mut stream, 400, &format!("Invalid payload: {e}"));
                        continue;
                    }
                };

                let result = dispatch_command(&task);

                let status_code = if result.status == "ok" { 200 } else { 500 };
                let _ = write_response(
                    &mut stream,
                    status_code,
                    &format!("{{\"status\":\"{}\",\"message\":\"{}\"}}", result.status, result.message),
                );                                              // line 69
            }
            Err(e) => {
                eprintln!("[handler] Accept error: {e}");
            }
        }
    }

    Ok(())
}

/// Read the body of an HTTP request from a TCP stream.
fn read_http_body(stream: &mut std::net::TcpStream) -> Result<String, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut content_length: usize = 0;

    // Read HTTP headers to find Content-Length.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().map_err(|e| format!("Invalid Content-Length: {e}"))?;
        }
    }

    if content_length == 0 {
        return Err("Missing Content-Length header".into());
    }

    if content_length > MAX_PAYLOAD_SIZE {
        return Err(format!("Payload exceeds {MAX_PAYLOAD_SIZE} byte limit"));
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;

    String::from_utf8(body).map_err(|e| e.to_string())
}

/// Parse a JSON task command from the request body.
///
/// Expected format:
/// ```json
/// {
///   "command_type": "read_file" | "write_file" | "shell_exec",
///   "path": "relative/path",
///   "content": "file content (for write_file)",
///   "command": "shell command (for shell_exec)"
/// }
/// ```
fn parse_task_command(body: &str) -> Result<TaskCommand, String> {
    // Simple JSON parsing without external dependencies.
    // In production this would use serde_json.
    let body = body.trim();
    if !body.starts_with('{') || !body.ends_with('}') {
        return Err("Body must be a JSON object".into());
    }

    let command_type = extract_json_string(body, "command_type")
        .ok_or("Missing 'command_type' field")?;

    Ok(TaskCommand {
        command_type,
        path: extract_json_string(body, "path"),
        content: extract_json_string(body, "content"),
        command: extract_json_string(body, "command"),
    })
}

/// Extract a simple string value from a JSON object by key.
/// This is a minimal parser; production code should use serde_json.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];

    // Skip whitespace and colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_space = after_colon.trim_start();

    if !after_space.starts_with('"') {
        return None;
    }

    let value_start = 1; // skip opening quote
    let rest = &after_space[value_start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Dispatch a parsed command to the appropriate tool.
fn dispatch_command(task: &TaskCommand) -> executor::ToolResult {
    match task.command_type.as_str() {
        "read_file" => {
            let path = match &task.path {
                Some(p) => p,
                None => {
                    return executor::ToolResult {
                        status: "error".into(),
                        message: "read_file requires 'path'".into(),
                    };
                }
            };
            executor::read_file(path)
        }
        "write_file" => {
            let path = match &task.path {
                Some(p) => p,
                None => {
                    return executor::ToolResult {
                        status: "error".into(),
                        message: "write_file requires 'path'".into(),
                    };
                }
            };
            let content = match &task.content {
                Some(c) => c,
                None => {
                    return executor::ToolResult {
                        status: "error".into(),
                        message: "write_file requires 'content'".into(),
                    };
                }
            };
            executor::write_file(path, content)
        }
        "shell_exec" => {
            let command = match &task.command {
                Some(c) => c,
                None => {
                    return executor::ToolResult {
                        status: "error".into(),
                        message: "shell_exec requires 'command'".into(),
                    };
                }
            };
            executor::shell_exec(command)
        }
        other => executor::ToolResult {
            status: "error".into(),
            message: format!("Unknown command type: {other}"),
        },
    }
}

/// Write an HTTP response to the stream.
fn write_response(
    stream: &mut std::net::TcpStream,
    status_code: u16,
    body: &str,
) -> Result<(), String> {
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code, status_text, body.len(), body
    );

    stream.write_all(response.as_bytes()).map_err(|e| e.to_string())
}
