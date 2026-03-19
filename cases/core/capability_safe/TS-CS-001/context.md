# TS-CS-001: Customer Support Agent — Host-Allowlisted API Fetching

## Scenario

A customer support agent retrieves ticket details and customer records from
external ticketing and CRM platforms (Zendesk, Salesforce, Freshdesk, HubSpot).
An LLM planner selects which API endpoints to call, and the agent's API client
tool executes the requests.

## Why this code is SAFE

The `api_client.ts` tool makes outbound HTTP requests, which superficially
resembles an SSRF pattern. However, every request passes through
`enforceHostAllowlist()` in `guards/host_policy.ts` **before** any network I/O
occurs. The guard parses the URL, extracts the hostname, and checks it against a
static `ReadonlySet` of approved hosts defined in `config/settings.ts`.

If the hostname is not in the allowlist, the guard throws a `HostPolicyError`
and no connection is opened. This prevents requests to internal services (e.g.,
cloud metadata endpoints), localhost, or any other unapproved target.

## Guard analysis

- **Guard type**: `host_allowlist`
- **Enforcement point**: `guards/host_policy.ts` — `enforceHostAllowlist()`
- **Called from**: `tools/api_client.ts` — `callApi()`, before `fetch()`
- **Allowlist source**: `config/settings.ts` — `APPROVED_HOSTS` (static, compile-time)
- **Scope**: Covers every code path that reaches `fetch()`; there is no bypass

## What a scanner should NOT report

A scanner should not flag the `fetch()` call in `api_client.ts` as SSRF because
the host allowlist guard ensures only pre-approved external hosts are reachable.
Flagging this would be a false positive.
