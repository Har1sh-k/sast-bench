# SB-TS-RW-015: Telegram webhook request bodies read before secret validation

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-jq3f-vjww-8rq7`
- Vulnerable commit: `1ef0aa443b2f5c9bc4825659d83a532998d8307b`
- Fix commit: `7e49e98f79073b11134beac27fdff547ba5a4a02`

## Scenario

OpenClaw exposes a Telegram webhook endpoint via a Node.js HTTP server. When Telegram sends updates, it includes a secret token header (`X-Telegram-Bot-Api-Secret-Token`) that the server must validate before processing. The webhook handler is configured with a 1 MB body size limit and a 30-second body read timeout, and relies on the grammy library's `webhookCallback` for dispatching updates after the body has been fully read.

## Vulnerability

In the vulnerable code, when a POST request arrives at the webhook path, the handler immediately calls `readJsonBodyWithLimit()` to consume and parse the entire request body (lines 143-149). Only after the body is fully read and parsed does the handler extract the secret token header (lines 178-179) and pass it to grammy's callback for validation (line 181). This ordering means any unauthenticated client can force the server to allocate up to 1 MB of memory and hold a connection open for up to 30 seconds before the request is rejected. An attacker can exploit this to exhaust server resources through parallel slow-drip or large-body requests without ever providing a valid secret token.

The fix moves the secret header validation to occur synchronously at the top of the request handler, immediately after logging, and before any body reading takes place. It also uses a timing-safe comparison via `crypto.timingSafeEqual` to prevent timing side-channel leakage of the secret value.

## Source / Carrier / Sink
- Source: unauthenticated HTTP POST request to the webhook path
- Carrier: `readJsonBodyWithLimit(req, ...)` reads up to 1 MB with a 30-second timeout before any authentication check
- Sink: resource consumption (memory allocation and connection hold) occurs unconditionally for all requests
- Missing guard: secret token header validation should occur before body reading begins

## Scanner Expectation
A scanner should flag the webhook request handler region (lines 139-168 of `src/telegram/webhook.ts`) for performing expensive I/O operations (body reading and parsing) before validating the authentication secret header. The core issue is that unauthenticated requests can consume server resources because the authentication check is deferred until after body consumption completes.
