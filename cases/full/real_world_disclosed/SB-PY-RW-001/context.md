# SB-PY-RW-001: browser-use allowed_domains bypass via HTTP auth URL syntax

## Advisory
- Repo: `browser-use/browser-use`
- GHSA: `GHSA-x39x-9qw5-ghrf`
- CVE: `CVE-2025-47241`
- Vulnerable commit: `5a45bf836ca93e3668f5678db0386c1e6d773a1b`
- Fix commit: `ebdeb613f7bdcbdc9d32eb1b850b9b8c8f71dfae`
- Patched in: 0.1.45

## Scenario

browser-use is a Python library that lets AI agents control a web browser.
`BrowserContext` has an `allowed_domains` config to restrict which domains
the agent can navigate to. Before every navigation, `_is_url_allowed()`
checks the URL against this allowlist.

## Vulnerability

`_is_url_allowed()` extracts the domain from `urlparse(url).netloc` and
then calls `domain.split(':')[0]` to strip the port. However, `netloc`
includes the HTTP Basic Auth prefix (`user:password@host`). A URL like
`https://allowed.com:pass@malicious.com` produces a `netloc` of
`allowed.com:pass@malicious.com`. Splitting on `:` yields `allowed.com`,
which passes the allowlist check, but the browser actually navigates to
`malicious.com`.

## Source / Carrier / Sink
- Source: model-generated URL (agent decides where to navigate)
- Carrier: `_is_url_allowed()` domain extraction in `context.py`
- Sink: browser navigation after allowlist check passes
- Missing guard: `parsed_url.hostname` should be used instead of
  manual `netloc` + `split(':')` parsing

## Annotated Region
- File: `browser_use/browser/context.py`
- Lines: 738-761
- Why this region is the scoring target: it contains the entire
  `_is_url_allowed()` method including the flawed domain extraction
  at line 747 (`parsed_url.netloc`) and the incorrect port-stripping
  at line 755 (`domain.split(':')[0]`)

## Scanner Expectation
A scanner should flag the `_is_url_allowed()` method for using
`urlparse().netloc` with manual colon-splitting instead of
`urlparse().hostname`, enabling URL-based SSRF through auth prefix
injection.
