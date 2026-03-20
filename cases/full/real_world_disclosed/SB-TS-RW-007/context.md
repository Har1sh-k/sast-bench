# SB-TS-RW-007: system.run approvals did not bind PATH-token executable identity

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q399-23r3-hfx4`
- Vulnerable commit: `611dff985d4ecc442633a740f0918d9eb5c6bf36`
- Fix commit: `78a7ff2d50fb3bcef351571cb5a0f21430a340c1`

## Scenario

OpenClaw's gateway implements an approval system for `system.run` commands, where dangerous commands must be approved by an operator before execution. When a node requests to run a command, the CLI sends an approval request with the command details. After the operator approves, the CLI sends the execution request with the approval record ID. The `sanitizeSystemRunParamsForForwarding` function validates the approval and forwards the sanitized parameters to the node host for execution.

## Vulnerability

The `sanitizeSystemRunParamsForForwarding` function (lines 87-123 of `node-invoke-system-run-approval.ts`) validates the approval record's run ID, node binding, device identity, and decision. However, the command parameters it forwards -- `command`, `rawCommand`, `cwd`, `agentId`, and `sessionKey` -- are taken from the caller's raw request parameters via `pickSystemRunParams` (line 120), not from the approval record. This means an attacker who obtains approval for a safe command like `echo hello` can substitute the command with `rm -rf /` in the forwarded execution request, and the gateway will accept it because the approval ID still matches. The execution plan is not cryptographically bound to the approval: only the run ID and node/device identity are verified, while the actual command content is mutable between approval and execution. Lines 102-111 resolve the command text from caller-supplied params `p.command` and `p.rawCommand` rather than from an immutable plan frozen at approval time.

## Source / Carrier / Sink
- Source: caller-supplied `rawParams` containing `command`, `rawCommand`, `cwd`, `agentId`, and `sessionKey` fields
- Carrier: `pickSystemRunParams` copies caller-supplied values into the forwarded parameters without binding them to the approved execution plan
- Sink: the node host executes the forwarded command parameters, which may differ from what was actually approved
- Missing guard: the fix introduces `system.run.prepare` to freeze an immutable `SystemRunApprovalPlanV2` at approval time, and `sanitizeSystemRunParamsForForwarding` now substitutes caller-supplied values with the plan's frozen values

## Scanner Expectation
A scanner should flag the `sanitizeSystemRunParamsForForwarding` function for using caller-supplied command parameters (`p.command`, `p.rawCommand`, `p.cwd`) in the forwarded execution request instead of values bound to the approval record. The vulnerability is a TOCTOU (time-of-check-time-of-use) issue where the approved command identity can be swapped between approval and execution.
