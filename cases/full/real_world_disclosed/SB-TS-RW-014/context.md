# SB-TS-RW-014: Cross-origin redirects preserved custom authorization headers in fetchWithSsrFGuard

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-6mgf-v5j7-45cr`
- Vulnerable commit: `eec5a6d6f187777ad3c8788cc8443af9e617ba5c`
- Fix commit: `c0cd5a72652901f0e039b539f9bf27109859abec`

## Scenario

OpenClaw includes a `fetchWithSsrFGuard` function that wraps HTTP fetch with SSRF protections: DNS pinning, internal IP blocking, and manual redirect following with loop and depth limits. The function is used throughout the codebase to make outbound HTTP requests to external services. Callers typically attach `Authorization` headers with bearer tokens or API keys, and may include `Cookie` headers for session-based APIs.

## Vulnerability

The redirect-following loop (lines 136-156) resolves the `Location` header to an absolute URL, checks for redirect loops and depth limits, but then continues the `while` loop with the same `params.init` object, which carries all original request headers. When a redirect crosses origin boundaries (e.g., from `api.example.com` to `cdn.attacker.com`), the `Authorization`, `Cookie`, and `Proxy-Authorization` headers from the original request are forwarded to the new origin. An attacker who controls a redirect target receives the victim's credentials. Standard browser fetch implementations strip sensitive headers on cross-origin redirects per the Fetch specification, but this manual redirect implementation does not. The fix adds a `stripSensitiveHeadersForCrossOriginRedirect` function that removes `authorization`, `proxy-authorization`, `cookie`, and `cookie2` headers when the redirect target has a different origin from the current URL.

## Source / Carrier / Sink
- Source: caller-supplied `Authorization`, `Cookie`, and `Proxy-Authorization` headers in `params.init`
- Carrier: the redirect-following loop at lines 147-156 which sets `currentUrl` to the cross-origin redirect target without modifying the request init or stripping headers
- Sink: the `fetcher(parsedUrl.toString(), init)` call at line 134 on the next loop iteration, which sends the original sensitive headers to the attacker-controlled redirect target
- Missing guard: cross-origin redirect detection and sensitive header stripping before following the redirect

## Scanner Expectation
A scanner should flag the redirect-following logic for preserving the original request headers (including Authorization and Cookie) when following redirects to a different origin, enabling credential leakage to attacker-controlled domains via open redirect or server-side redirect chains.
