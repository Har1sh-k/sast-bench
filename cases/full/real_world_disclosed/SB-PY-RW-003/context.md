# SB-PY-RW-003: AutoGPT RSS block fetches arbitrary feed URLs

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-r55v-q5pc-j57f`
- CVE: `CVE-2025-62615`
- Vulnerable commit: `9469b9e2eb4504a75147f5026d83790f219e64df`
- Fix commit: `e2a9923f3056157b89f6659bb1a201e301eff0f7`
- Patched in: `autogpt-platform-beta-v0.6.34`

## Scenario

AutoGPT includes a block-based backend where agents can ingest external RSS
feeds and turn feed entries into downstream tasks. `ReadRSSFeedBlock` accepts
an `rss_url` input and repeatedly fetches the feed while an agent workflow is
running.

## Vulnerability

`parse_feed()` checks only that the scheme is `http` or `https`, then calls
`urllib.request.urlopen(url, timeout=30)` directly. That bypasses the
repository's hardened `Requests()` helper, which is used elsewhere to enforce
host validation and SSRF protections. A malicious workflow input can therefore
target loopback, link-local, or cloud-metadata endpoints.

## Source / Carrier / Sink
- Source: user- or model-controlled `input_data.rss_url`
- Carrier: `ReadRSSFeedBlock.parse_feed()` in `rss.py`
- Sink: `urllib.request.urlopen(url, timeout=30)`
- Missing guard: host validation / private-IP blocking via the shared
  `Requests()` network wrapper

## Annotated Region
- File: `autogpt_platform/backend/backend/blocks/rss.py`
- Lines: 106-138
- Why this region is the scoring target: it contains the full vulnerable
  helper, including the scheme-only validation and the direct `urlopen` call

## Scanner Expectation
A scanner should flag the flow from `rss_url` into `urllib.request.urlopen`
without the repository's standard SSRF guard path.
