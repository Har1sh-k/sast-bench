# SB-TS-RW-021: Unauthenticated config.apply via permissive default in gateway method authorization

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-g55j-c2v4-pjcg`
- Vulnerable commit: `32a668e4d99b2f9efbe2112aee0064b816f0b2ef`
- Fix commit: `9dbc1435a6cac576d5fd71f4e4bff11a5d9d43ba`

## Scenario

OpenClaw exposes a WebSocket-based gateway that dispatches JSON-RPC method calls to server-side handlers. The `handleGatewayRequest` function in `src/gateway/server-methods.ts` calls `authorizeGatewayMethod` to check whether a client is permitted to invoke a given method before dispatching it. The gateway registers handlers for numerous method namespaces including `config.*`, `wizard.*`, `update.*`, `sessions.*`, `cron.*`, and `skills.*`, all of which can mutate server state.

## Vulnerability

The `authorizeGatewayMethod` function (lines 45-67) uses an allowlist approach for a narrow set of sensitive methods but falls through to a permissive default for everything else. Specifically:

1. **Unauthenticated access on line 46:** `if (!client?.connect) return null;` immediately permits any request where the client has no connection metadata, meaning unauthenticated local WebSocket clients are allowed through without any further checks.

2. **Permissive default on line 66:** After checking a small set of explicit blocks (approval methods require `operator.approvals` scope, pairing methods require `operator.pairing` scope, and methods with the `exec.approvals.` prefix require `operator.admin`), the function returns `null` (permit) as its default case. Any method not matching one of those explicit checks passes through unchallenged.

This means methods like `config.apply`, `wizard.*`, `update.*`, `sessions.*`, `cron.add`, `cron.remove`, `skills.install`, and `channels.logout` are all accessible without any scope or authentication requirement. An unauthenticated local client can call `config.apply` to write arbitrary configuration, including setting `cliPath` to point to a malicious binary, which is then executed by the gateway -- achieving local remote code execution.

The fix introduces explicit `READ_METHODS` and `WRITE_METHODS` sets with corresponding `operator.read` and `operator.write` scope requirements, explicitly enumerates admin-level methods (config, wizard, update, sessions mutation, cron mutation, skills installation), and changes the default from `return null` (permit) to `return errorShape(...)` (deny). This converts the authorization model from default-allow to default-deny.

## Source / Carrier / Sink
- Source: unauthenticated WebSocket client sending a JSON-RPC method call (e.g., `config.apply`)
- Carrier: `authorizeGatewayMethod` function that returns `null` (permit) for any method not in the explicit block lists
- Sink: `configHandlers` process the `config.apply` call and write attacker-controlled configuration including `cliPath`, leading to arbitrary command execution
- Missing guard: default-deny authorization and scope requirements for state-mutating methods

## Scanner Expectation
A scanner should flag the `authorizeGatewayMethod` function (lines 45-67 of `src/gateway/server-methods.ts`) for its permissive default authorization policy. The function only restricts a small subset of methods (approval, pairing, and `exec.approvals.*` prefix) and returns `null` (permit) for all others, including security-critical methods like `config.apply` that can write arbitrary server configuration. The vulnerability pattern is a default-allow authorization check in a method dispatch gate that should be default-deny.
