# SB-TS-RW-017: WebSocket shared-auth connections could self-declare elevated scopes

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-rqpp-rjj8-7wv8`
- Vulnerable commit: `55f47e5ce658bf3bdcb3eac3a2a5b4ed4aa9f5ce`
- Fix commit: `5e389d5e7c9233ec91026ab2fea299ebaf3249f6`

## Scenario

OpenClaw's gateway server accepts WebSocket connections from various client types. During the connection handshake in `message-handler.ts`, a `connect` frame carries client-declared scopes (operator permissions). The handler includes a `clearUnboundScopes` function that is supposed to strip self-declared scopes from connections that lack a verified device identity, and a `handleMissingDeviceIdentity` function that decides whether to proceed or reject connections without device credentials.

## Vulnerability

The `clearUnboundScopes` function at line 645 contains a guard condition `if (scopes.length > 0 && !controlUiAuthPolicy.allowBypass && !sharedAuthOk)` that exempts shared-auth connections and control-UI bypass scenarios from having their scopes cleared. This means a WebSocket client authenticating via shared-auth (e.g., a shared password or token) can include arbitrary elevated scopes in its connect frame and those scopes will be preserved. Additionally, `handleMissingDeviceIdentity` at line 651 unconditionally calls `clearUnboundScopes` when no device is present, but the inner guard condition prevents scope clearing for shared-auth connections. The result is that a shared-auth client without a device identity retains whatever operator scopes it self-declared.

The fix simplifies `clearUnboundScopes` to unconditionally clear scopes when they exist, and moves the call site to only invoke scope clearing after the full `evaluateMissingDeviceIdentity` decision has been made, and only when the connection lacks both a device identity and the control-UI allow decision.

## Source / Carrier / Sink
- Source: client-supplied `scopes` array in the WebSocket connect frame
- Carrier: `clearUnboundScopes` function with overly permissive guard condition that preserves scopes for shared-auth
- Sink: `connectParams.scopes` retains elevated operator permissions for the session
- Missing guard: scope clearing should be unconditional for connections without verified device identity, regardless of auth method

## Scanner Expectation
A scanner should flag the `clearUnboundScopes` and `handleMissingDeviceIdentity` region (lines 645-674) for allowing client-declared scopes to persist on shared-auth connections that lack device identity verification. The vulnerability pattern is a conditional authorization check that can be bypassed by a specific authentication method, permitting self-elevation of privileges.
