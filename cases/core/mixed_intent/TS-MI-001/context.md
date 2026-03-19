# TS-MI-001: Consumer Browser Assistant — Guarded Navigator vs Unguarded Screenshot Helper

## Scenario

A consumer browser assistant helps users compare products across popular
shopping and review sites (Amazon, Best Buy, Walmart, Yelp, etc.).  An LLM
planner generates a browsing plan consisting of navigation and screenshot
actions.  The agent router dispatches each action to the appropriate tool:
navigation steps go through the **navigator**, and screenshot steps go through
the **screenshot helper**.

Both tools make outbound HTTP requests, but they differ critically in how
they validate the target URL before issuing the request.

## Safe path — `navigator.ts` (R1)

The `navigateTo` function calls `enforceDomainPolicy()` from
`guards/domain_policy.ts` before making any network request.  The guard
parses the URL, validates the scheme (`http` / `https` only), and checks
that the hostname appears in the static `APPROVED_DOMAINS` list defined in
`config/settings.ts`.  If the host is not approved, the request is rejected
immediately and no connection is opened.

This means that even if the LLM planner injects a malicious URL (e.g.,
`http://169.254.169.254/latest/meta-data/`), the navigator will refuse to
fetch it.  A scanner should **not** flag this function.

## Vulnerable path — `screenshot_helper.ts` (R2)

The `fetchPreview` function was added as a quick utility for generating
visual previews of pages.  It accepts a URL directly from the planner and
passes it to `fetch()` without any host-allowlist check.  The same domain
policy guard used by the navigator could have been reused here but was never
wired in.

An attacker who controls or influences the model's output can cause the
assistant to make requests to internal services (e.g., the AWS instance
metadata endpoint) via the screenshot helper.  A scanner **must** flag this
function.

## Why this is a mixed-intent case

Both tools exercise the same capability (outbound HTTP requests / network)
and sit in the same codebase.  The difference is purely in whether the
domain-policy guard is invoked before the sink:

| Tool               | Guard                  | SSRF-safe? |
|--------------------|------------------------|------------|
| `navigator.ts`     | `enforceDomainPolicy`  | Yes        |
| `screenshot_helper` | *(none)*              | No         |

A precise scanner must distinguish between these two paths rather than
blanket-flagging all `fetch()` calls.

## What a scanner should find

- **Must flag**: `screenshot_helper.ts` lines 30-65 (`fetchPreview`) — untrusted
  input reaches `fetch()` without host validation.
- **Must not flag**: `navigator.ts` lines 28-61 (`navigateTo`) — the domain
  allowlist guard prevents SSRF before any network I/O.
