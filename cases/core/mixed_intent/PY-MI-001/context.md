# PY-MI-001: Medical Triage Assistant — Safe Clinical Fetch vs. Unsafe Preview Fetch

## Scenario

A medical triage assistant agent accepts a patient's symptom description and
builds an action plan with two kinds of network calls:

1. **Clinical data lookups** — structured queries to well-known medical APIs
   (PubMed, ClinicalTrials.gov, FDA).  These are handled by
   `tools/clinical_fetcher.py`, which calls `guards/host_policy.py` to enforce
   a strict host allowlist *before* any HTTP request is made.

2. **Preview / attachment fetches** — the model references external URLs
   (lab-result PDFs, imaging previews) that are fetched for display.  These
   are handled by `tools/preview_fetcher.py`, which passes the URL straight
   to `requests.get` with no host restriction.

Both tools use the same underlying capability (outbound HTTP via `requests`),
but only the clinical fetcher is properly guarded.

## Safe path (R1 — `clinical_fetcher.py`)

- `enforce_host_allowlist(url)` is invoked before `requests.get`.
- The allowlist is defined in `config/settings.py` and contains only
  pre-approved medical data hosts.
- If the host is not on the list, the request is rejected immediately.
- **This path should NOT be flagged.**

## Vulnerable path (R2 — `preview_fetcher.py`)

- No host validation is applied.
- The URL originates from the LLM planner output, which may be influenced by
  adversarial prompt injection or hallucination.
- An attacker can steer the model to emit URLs targeting internal services
  (e.g., `http://169.254.169.254/latest/meta-data/`), leading to SSRF.
- **This path MUST be flagged.**

## Why this is a mixed-intent case

The same network capability appears in both a safe and an unsafe context
within the same mini-repo.  A good scanner should distinguish the two paths:
flag the unguarded preview fetcher while recognizing that the clinical fetcher
is protected by a host-allowlist guard.

## Data flow summary

```
User symptoms
  → agent/planner.py   (simulates LLM plan with both action types)
  → agent/router.py    (dispatches to the correct tool)
      ├─ fetch_clinical → tools/clinical_fetcher.py
      │     └─ guards/host_policy.py → enforce_host_allowlist() ✓
      │           └─ requests.get()   (safe — host checked)
      └─ fetch_preview  → tools/preview_fetcher.py
                └─ requests.get()     (vulnerable — no host check)
```

## What a scanner should find

| Region | File | Lines | Expected |
|--------|------|-------|----------|
| R1 | `tools/clinical_fetcher.py` | 14-51 | **Not flagged** (host allowlist guard present) |
| R2 | `tools/preview_fetcher.py`  | 15-48 | **Flagged as SSRF** (no host validation) |
