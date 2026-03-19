# TS-SV-002: Travel Planning Agent — Unrestricted URL Fetching

## Scenario

A browser-based travel planning agent helps users research trips by fetching
hotel listings, airline prices, weather forecasts, and destination guides from
URLs produced by an LLM planner. The agent collects these pages, extracts
relevant metadata, and presents a consolidated travel summary.

## Vulnerability

The `url_fetcher.ts` tool accepts URLs directly from the agent planner and
passes them to an HTTP client (`fetch`) without any host allowlist or scheme
restriction. An attacker who controls or influences the model's output can
cause the agent to make requests to internal services (e.g., the AWS instance
metadata endpoint at `http://169.254.169.254/latest/meta-data/`).

## Why this is vulnerable

- **Source**: LLM planner output (model-controlled URL)
- **Carrier**: Agent router passes planner output to the URL fetcher tool
- **Sink**: `fetch(url)` in `url_fetcher.ts`
- **Missing guard**: No host allowlist, no scheme restriction, no private-IP blocking

## What a scanner should find

A finding on `url_fetcher.ts` lines 16-47 indicating that untrusted input
reaches an outbound HTTP request without URL validation.
