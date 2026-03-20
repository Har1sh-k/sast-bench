# SB-PY-RW-004: AutoGPT Discord file sender downloads arbitrary URLs

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-ggc4-4fmm-9hmc`
- CVE: `CVE-2025-62616`
- Vulnerable commit: `9469b9e2eb4504a75147f5026d83790f219e64df`
- Fix commit: `e2a9923f3056157b89f6659bb1a201e301eff0f7`
- Patched in: `autogpt-platform-beta-v0.6.34`

## Scenario

AutoGPT includes Discord integration blocks that can send generated files back
to a Discord channel. `SendDiscordFileBlock` accepts a `file` input that can
be raw bytes, a local file path, or an HTTP(S) URL to download before upload.

## Vulnerability

When `file` starts with `http://` or `https://`, the block downloads it via
`aiohttp.ClientSession().get(file)` and forwards the bytes to Discord. The
input URL is not checked against the repository's SSRF protections, so agent
workflows can be coerced into fetching loopback, link-local, or metadata
endpoints.

## Source / Carrier / Sink
- Source: user- or model-controlled `file` field
- Carrier: `SendDiscordFileBlock.run()` URL branch in `bot_blocks.py`
- Sink: `session.get(file)` followed by `response.read()`
- Missing guard: host validation / private-IP blocking via the shared
  `Requests()` helper

## Annotated Region
- File: `autogpt_platform/backend/backend/blocks/discord/bot_blocks.py`
- Lines: 700-711
- Why this region is the scoring target: it contains the exact URL-handling
  branch where untrusted input flows into the network sink

## Scanner Expectation
A scanner should flag the HTTP(S) download branch for issuing an outbound
request from untrusted agent input without SSRF guard logic.
