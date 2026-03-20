# RS-SV-004: Multi-Agent Orchestrator — Unauthenticated Command Endpoint

## Scenario

A multi-agent orchestration system coordinates work across several
specialised agents. The coordinator agent exposes an HTTP endpoint that
accepts JSON task payloads from peer agents. Each payload specifies a
command type (file read, file write, shell exec) and the associated
parameters. The handler parses the JSON and dispatches the operation
to the appropriate internal tool.

## Vulnerability

The `handler.rs` module accepts and dispatches commands from any network
client without verifying caller identity. There is no authentication
token, no mTLS check, no peer identity validation, and no authorization
guard. Any client that can reach the HTTP endpoint can execute file
operations and shell commands as if it were a trusted peer agent.

## Why this is vulnerable

- **Source**: Incoming HTTP request body (any network client)
- **Carrier**: HTTP handler parses JSON and dispatches to tools
- **Sink**: Tool invocations in `handler.rs` dispatch logic
- **Missing guard**: No authentication (token, mTLS, peer certificate),
  no authorization check

## What a scanner should find

A finding on `handler.rs` lines 25-78 indicating that the HTTP handler
accepts and dispatches privileged commands without any caller
authentication, allowing unauthenticated access to internal tools.
