# SB-TS-RW-016: Bootstrap setup codes could be replayed to escalate pending pairing scopes

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-63f5-hhc7-cx6p`
- Vulnerable commit: `ae1a1fccfeac598a747a9b4a6c9871c93061229c`
- Fix commit: `1803d16d5cec970c54b0e1ac46b31b1cbade335c`

## Scenario

OpenClaw uses a device bootstrap flow where a one-time setup token is issued and then verified when a new device pairs. The `verifyDeviceBootstrapToken` function in `src/infra/device-bootstrap.ts` looks up a token record from a persisted JSON state file, validates the token, and then updates the record with the caller-supplied device identity and permissions before persisting the state back to disk.

## Vulnerability

The `verifyDeviceBootstrapToken` function (lines 85-133) does not consume (delete) the bootstrap token after successful verification. Instead, it uses `mergeRoles` and `mergeScopes` helper functions to additively merge the caller-supplied roles and scopes into the existing token record (lines 121-125). This means the same bootstrap token can be presented multiple times with different role and scope parameters. Each replay adds to the set of permissions on the pending pairing record, allowing privilege escalation. The token record also allows re-binding to a different deviceId and publicKey if the fields were not previously set, or it accepts the same values if they match -- but it never invalidates the token.

The fix replaces the merge-and-update logic with a single `delete state[entry.token]` call, ensuring the bootstrap token is consumed on first use and cannot be replayed.

## Source / Carrier / Sink
- Source: caller-supplied `role` and `scopes` parameters to `verifyDeviceBootstrapToken`
- Carrier: `mergeRoles` and `mergeScopes` functions additively merge new permissions into existing record
- Sink: persisted state file is updated with escalated permissions via `persistState`
- Missing guard: token should be consumed (deleted) after first successful verification to prevent replay

## Scanner Expectation
A scanner should flag the `verifyDeviceBootstrapToken` function (lines 85-133) for failing to invalidate the bootstrap token after successful verification, enabling token replay with escalating permissions. The critical pattern is a one-time credential that is verified but never consumed, combined with additive merging of caller-controlled authorization parameters.
