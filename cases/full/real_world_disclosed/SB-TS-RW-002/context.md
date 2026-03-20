# SB-TS-RW-002: OpenCode XSS to RCE via unsanitized web UI URL parameter

## Advisory
- Repo: `anomalyco/opencode`
- GHSA: `GHSA-c83v-7274-4vgp`
- CVE: `CVE-2026-22813`
- Vulnerable commit: `18cf4df6c6a7175334485252c4c772921f07f93f`
- Fix commit: `cbb3141130105287302de927af6d016ecce68219`
- Additional hardening: `0f2124db3260` (no inline JS), `982b71e861e5` (disable server unless explicitly opted in)
- Patched in: v1.1.10

## Scenario

OpenCode is an AI coding assistant with a web UI served on
`localhost:4096`. The SolidJS frontend connects to a backend server
URL that is determined at startup by the `defaultServerUrl` function
in `app.tsx`.

## Vulnerability

`defaultServerUrl` (lines 40-42) reads a `?url=` query parameter from
`document.location.search` and, if present, returns it directly as the
backend server URL with no validation:

```typescript
const param = new URLSearchParams(document.location.search).get("url")
if (param) return param
```

An attacker crafts a link such as
`http://localhost:4096/?url=https://evil.example.com` and tricks a user
into opening it. The UI then connects to the attacker-controlled server,
which returns malicious LLM responses containing unsanitized HTML/JS.
Because the UI renders model output without sanitization, this achieves
XSS in the browser context of the local application.

From the XSS foothold the attacker's JavaScript reaches the `/pty/`
WebSocket endpoints exposed by the OpenCode backend, which can spawn
arbitrary shell processes on the host machine, completing the chain
from link click to full remote code execution.

## Source / Carrier / Sink
- Source: `?url=` query parameter in browser location (`document.location.search`)
- Carrier: `defaultServerUrl` returns the parameter value as the backend URL
- Sink: the UI connects to the attacker-controlled server, renders
  unsanitized responses (XSS), and the XSS payload uses `/pty/`
  endpoints to execute arbitrary commands
- Missing guard: no validation or allowlist on the `url` parameter;
  fix removes the parameter entirely

## Annotated Region
- File: `packages/app/src/app.tsx`
- Lines: 40-42
- Why this region is the scoring target: it contains the
  `defaultServerUrl` IIFE entry point where the attacker-controlled
  `?url=` query parameter is read and returned as the server URL
  without any validation, enabling the full XSS-to-RCE chain

## Scanner Expectation
A scanner should flag the flow from `document.location.search` through
`URLSearchParams.get("url")` being used as a backend server URL without
validation, recognizing that user-controlled URL redirection enables
XSS and subsequent command execution via PTY endpoints.
