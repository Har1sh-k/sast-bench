# SB-TS-RW-013: Trusted-proxy browser WebSocket handshakes could bypass origin validation

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-5wcw-8jjv-m286`
- Vulnerable commit: `3c0fd3dffe67759f60685a6fb1b016f0d6f5f3cd`
- Fix commit: `ebed3bbde1a72a1aaa9b87b63b91e7c04a50036b`

## Scenario

OpenClaw's gateway server accepts WebSocket connections from various clients including browser-based Control UI operators. When running in `trusted-proxy` mode behind a reverse proxy, the gateway relies on forwarded headers (X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-User) to authenticate operators. Browser connections should also be validated against an `allowedOrigins` list to prevent cross-site WebSocket hijacking. The `resolveHandshakeBrowserSecurityContext` function determines whether origin checks should be enforced for incoming connections.

## Vulnerability

At line 117, `enforceOriginCheckForAnyClient` is computed as `hasBrowserOriginHeader && !params.hasProxyHeaders`. In trusted-proxy deployments, the reverse proxy always injects forwarded headers, so `hasProxyHeaders` is always true. This causes `enforceOriginCheckForAnyClient` to be false for every browser connection arriving through the proxy, completely disabling origin validation. An attacker hosting a malicious website can establish a cross-origin WebSocket connection through the trusted proxy. Because the proxy forwards authentication headers (e.g., `X-Forwarded-User`) and origin checks are skipped, the attacker's browser connection is authenticated as the proxied operator with `operator.admin` scopes, enabling full cross-site WebSocket hijacking.

## Source / Carrier / Sink
- Source: attacker-controlled browser Origin header from a malicious website, arriving through the trusted reverse proxy with forwarded authentication headers
- Carrier: `resolveHandshakeBrowserSecurityContext` at line 117 which disables origin enforcement when proxy headers are present
- Sink: the WebSocket handshake handler accepts the connection without origin validation, granting the attacker authenticated operator access
- Missing guard: origin validation must be enforced for all browser connections regardless of whether proxy headers are present; the proxy header presence should not suppress origin checks

## Scanner Expectation
A scanner should flag the `enforceOriginCheckForAnyClient` computation at line 117 where the presence of proxy headers (`!params.hasProxyHeaders`) incorrectly suppresses browser origin validation, creating a cross-site WebSocket hijacking vulnerability in trusted-proxy deployments.
