# PY-SV-001: Medical Research Agent — Unrestricted Reference Fetching

## Scenario

A medical research agent assists clinicians by fetching academic references,
imaging data, and supplementary materials from URLs suggested by an LLM planner.

## Vulnerability

The `reference_fetcher.py` tool accepts URLs directly from the agent planner
and passes them to `requests.get()` without any host allowlist or scheme
restriction. An attacker who controls or influences the model's output can
cause the agent to make requests to internal services (e.g., cloud metadata
endpoints, internal APIs).

## Why this is vulnerable

- **Source**: LLM planner output (model-controlled URL)
- **Carrier**: Agent router passes planner output to the fetch tool
- **Sink**: `requests.get(url)` in `reference_fetcher.py`
- **Missing guard**: No host allowlist, no scheme restriction

## What a scanner should find

A finding on `reference_fetcher.py` lines 15-34 indicating that untrusted
input reaches an outbound HTTP request without URL validation.
