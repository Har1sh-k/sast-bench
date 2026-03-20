# SB-PY-RW-005: AutoGPT request wrapper is vulnerable to DNS rebinding SSRF

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-wvjg-9879-3m7w`
- CVE: `CVE-2025-31490`
- Vulnerable commit: `90b147ff51ea0313547e0c282b68f73564e419f6`
- Fix commit: `c6703dd89128b59f1fab79dc38eaa8e24009adce`
- Patched in: `autogpt-platform-beta-v0.6.1`

## Scenario

AutoGPT uses a shared `Requests` wrapper to centralize outbound HTTP access for
blocks and agent workflows. The wrapper is intended to stop SSRF by validating
the destination hostname before allowing the request to proceed.

## Vulnerability

The wrapper validates the original hostname with `validate_url()`, but then
passes the hostname-based URL back into `requests.request()`. That call
performs a second DNS resolution. With a rebinding hostname that first resolves
to a public address and then re-resolves to a blocked internal address, the
guard is bypassed and the request reaches the internal destination.

## Source / Carrier / Sink
- Source: user- or model-controlled `url` passed into `Requests.request()`
- Carrier: `validate_url()` result is reused as a hostname URL, not pinned to a
  validated IP
- Sink: `req.request(method, url, ...)`
- Missing guard: destination pinning to a validated IP plus host-header / SNI
  handling for the original hostname

## Annotated Region
- File: `autogpt_platform/backend/backend/util/request.py`
- Lines: 130-182
- Why this region is the scoring target: it contains the request wrapper logic
  that validates once, then re-resolves on the actual outbound request and on
  redirects

## Scanner Expectation
A scanner should flag the wrapper as SSRF-prone because the validated hostname
is not pinned to the resolved IP before the outbound request is made.
