# SB-TS-RW-011: node.invoke allowed untrusted system.run approval fields to bypass exec approvals

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-gv46-4xfq-jv58`
- Vulnerable commit: `c15946274ed62cce3846f0feea723bc83404b462`
- Fix commit: `0af76f5f0e93540efbdf054895216c398692afcd`

## Scenario

OpenClaw's gateway supports remote node invocation through the `node.invoke` handler. When an operator invokes a command on a paired node, the gateway validates the command against an allowlist and, for `system.run` commands specifically, sanitizes the parameters through `sanitizeSystemRunParamsForForwarding` to strip or validate exec approval fields. This sanitization ensures that untrusted clients cannot forge approval tokens to bypass the exec approval manager.

## Vulnerability

The `node.invoke` handler at lines 421-428 uses an inline conditional that only routes through `sanitizeSystemRunParamsForForwarding` when `command === "system.run"`. For all other commands, it constructs `{ ok: true, params: p.params }` directly, forwarding the raw client-supplied parameters without any sanitization. This means a command that carries system.run-style approval fields (or any other security-sensitive parameter structure) is forwarded verbatim to the target node. The fix extracts this logic into a dedicated `sanitizeNodeInvokeParamsForForwarding` function that centralizes parameter sanitization for all commands, not just `system.run`.

## Source / Carrier / Sink
- Source: untrusted `p.params` from the client's `node.invoke` request, which may contain forged approval fields
- Carrier: the inline conditional at lines 421-428 that bypasses sanitization for non-`system.run` commands
- Sink: `context.nodeRegistry.invoke()` at line 439 which forwards the unsanitized parameters to the target node for execution
- Missing guard: centralized parameter sanitization that applies to all node invoke commands, not just `system.run`

## Scanner Expectation
A scanner should flag the conditional sanitization logic where non-`system.run` commands pass client-supplied parameters directly to the node invocation without any sanitization, allowing approval field injection that bypasses exec approval controls.
