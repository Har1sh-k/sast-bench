# SB-TS-RW-001: OpenCode unauthenticated HTTP server allows arbitrary command execution

## Advisory
- Repo: `anomalyco/opencode`
- GHSA: `GHSA-vxw4-wv6m-9hhh`
- CVE: `CVE-2026-22812`
- Vulnerable commit: `787f37b3827fb295452341a7e5b6a90a266f36f1`
- Fix commit: `7d2d87fa2c44e32314015980bb4e59a9386e858c`

## Scenario

OpenCode is a terminal-based AI coding assistant. It runs a local HTTP
server (Hono framework) that exposes an API for managing sessions, running
shell commands, creating pseudo-terminals, and reading files. The server
is intended to be consumed by the local TUI client.

## Vulnerability

The server applies `.use(cors())` at line 107 with no origin restriction,
meaning any website can make cross-origin requests to it. More critically,
there is no authentication middleware anywhere in the middleware chain.
Every endpoint is accessible to any process or website that can reach the
server's port.

The `POST /session/:sessionID/shell` endpoint (lines 1406-1437) accepts a
JSON body and passes it to `SessionPrompt.shell()`, which executes
arbitrary shell commands within the session context. An attacker who can
reach the server (e.g., via a malicious web page opened in the user's
browser) can execute arbitrary commands on the host machine with the
privileges of the OpenCode process.

Additional unauthenticated endpoints of concern include:
- `POST /pty` (line 274) -- create pseudo-terminal sessions
- `GET /file/content` -- read arbitrary file contents
- `PUT /pty/:ptyID` -- send input to running terminals

## Source / Carrier / Sink
- Source: unauthenticated HTTP request from any origin (cors() with no
  restriction)
- Carrier: Hono route handler at `/session/:sessionID/shell` with no
  auth middleware
- Sink: `SessionPrompt.shell({ ...body, sessionID })` executes shell
  commands
- Missing guard: authentication middleware and CORS origin restriction

## Annotated Region
- File: `packages/opencode/src/server/server.ts`
- Lines: 1406-1437
- Why this region is the scoring target: it contains the
  `POST /session/:sessionID/shell` route handler that accepts
  unauthenticated requests and invokes `SessionPrompt.shell()` to
  execute arbitrary commands. The unrestricted `cors()` at line 107
  enables cross-origin exploitation, but the shell endpoint itself
  is the direct command injection sink.

## Scanner Expectation
A scanner should flag the `/session/:sessionID/shell` endpoint for
accepting unauthenticated requests that lead to shell command execution
via `SessionPrompt.shell()`, with no authentication or authorization
checks in the request handling chain.
