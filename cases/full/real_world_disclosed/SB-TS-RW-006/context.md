# SB-TS-RW-006: sessions_spawn bypassed sandbox inheritance for ACP runtime

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-474h-prjg-mmw3`
- Vulnerable commit: `6a1eedf10b1b1cbdd25a2d6c8cc24b06b303ebd1`
- Fix commit: `b9aa2d436b757d2bd96c8bbaec35dbc1edf4dfb1`

## Scenario

OpenClaw supports multi-agent architectures where a parent agent can spawn subagent sessions via the `sessions_spawn` tool. Agents can be individually configured with sandbox modes (e.g., `"all"` for full sandboxing or `"off"` for no sandboxing). The `spawnSubagentDirect` function in `subagent-spawn.ts` validates that the target agent is in the requester's `allowAgents` list and enforces depth and concurrency limits before creating the child session.

## Vulnerability

After validating the agent allowlist (lines 254-270), `spawnSubagentDirect` directly creates the child session key at line 271 (`const childSessionKey = agent:${targetAgentId}:subagent:${crypto.randomUUID()}`), proceeds to set its depth and model (line 272 onward), and dispatches the task. At no point does the function check whether the requester session is sandboxed and, if so, whether the target agent's sandbox configuration would result in the child running unsandboxed. This means a sandboxed agent session can spawn a subagent targeting an agent configured with `sandbox.mode: "off"`, effectively escaping the sandbox. The child session runs with the target agent's own sandbox policy, which may grant unrestricted filesystem access, command execution, or network access that the sandboxed parent was denied.

## Source / Carrier / Sink
- Source: `params.agentId` in the `sessions_spawn` tool invocation, controlled by the sandboxed agent
- Carrier: `spawnSubagentDirect` creates the child session at line 271 without comparing requester vs. child sandbox status
- Sink: the child session runs under the target agent's sandbox policy, which may be `"off"`, granting unsandboxed access
- Missing guard: the fix adds `resolveSandboxRuntimeStatus` checks for both requester and child sessions, rejecting the spawn when `requesterRuntime.sandboxed && !childRuntime.sandboxed`

## Scanner Expectation
A scanner should flag the child session creation at line 271 for lacking a sandbox inheritance check between the requester and target agent. The vulnerability is a privilege escalation where a sandboxed session can spawn an unsandboxed child, bypassing the sandbox boundary. The key missing control is a comparison of the requester's sandbox status against the child's resolved sandbox status before proceeding with the spawn.
