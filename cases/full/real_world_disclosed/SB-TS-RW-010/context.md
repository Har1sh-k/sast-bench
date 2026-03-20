# SB-TS-RW-010: device.token.rotate could mint scopes broader than caller held

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-4jpw-hj22-2xmc`
- Vulnerable commit: `40a292619e1f2be3a3b1db663d7494c9c2dc0abf`
- Fix commit: `914a7c5359ccf3a0130da6517701cc8fb7ad86bd`

## Scenario

OpenClaw's gateway uses a device-pairing system where paired devices hold auth tokens with role-specific scopes (e.g., `operator.read`, `operator.admin`). Devices can rotate their tokens via the `rotateDeviceToken` function, optionally specifying new scopes. This is intended to allow down-scoping (e.g., narrowing from admin to read-only) but should never allow a device to escalate beyond its originally approved scope baseline.

## Vulnerability

The `rotateDeviceToken` function (lines 508-544) accepts a `scopes` parameter from the caller and passes it through `normalizeDeviceAuthScopes` without any containment check against the device's approved scope baseline. At line 525-527, the requested scopes default to the existing token scopes or device scopes if none are provided, but when explicit scopes are supplied, they are accepted unconditionally. The new token is minted at lines 529-535 with the requested scopes, and at line 539, `device.scopes` is updated to match. There is no `approvedScopes` field tracked, no scope implication hierarchy enforced, and no check that the requested scopes are a subset of what was originally approved. A device approved with `operator.read` can rotate with `scopes: ["operator.admin"]` to escalate privileges.

## Source / Carrier / Sink
- Source: caller-supplied `params.scopes` array passed to `rotateDeviceToken`
- Carrier: `requestedScopes` variable at line 525 which accepts the caller's scopes without validation
- Sink: `buildDeviceAuthToken` at line 529 mints a new token with the escalated scopes, and `device.scopes` is overwritten at line 539
- Missing guard: scope containment check comparing requested scopes against an `approvedScopes` baseline, with scope implication expansion (e.g., `operator.admin` implies `operator.read`)

## Scanner Expectation
A scanner should flag the `rotateDeviceToken` function for accepting caller-controlled scopes and minting a new auth token without verifying that the requested scopes are within the device's approved scope baseline, allowing privilege escalation via token rotation.
