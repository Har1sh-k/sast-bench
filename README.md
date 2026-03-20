# SASTbench

> Can your scanner find real vulnerabilities in agentic repos without flagging the code the agent is supposed to run?

SASTbench evaluates whether static analyzers can detect real vulnerabilities in agentic codebases without treating intentional agent capabilities as vulnerabilities.

## Quick Start

```bash
# Run benchmark against a scanner
python scripts/run.py --scanner semgrep --track core

# Validate case definitions
python scripts/validate.py

# Generate report
python scripts/report.py results/<results-file>.json
```

## Tracks

- **Core Track**: Self-contained, vendored cases. 5-minute quickstart, deterministic runs.
- **Full Track**: Core Track plus pinned snapshots from real public repositories.

## Status

- **17 Core Track** cases (synthetic vulnerable, capability safe, mixed intent)
- **27 Full Track** cases (real-world disclosed from public repositories)
- **44 total cases** across Python, TypeScript, and Rust

## Official Adapters

- `semgrep`
- `bandit`

## V1 Canonical Vulnerability Kinds

| Kind | Capability Surface |
|------|--------------------|
| `command_injection` | Executing commands |
| `path_traversal` | Reading and writing files |
| `ssrf` | Making outbound network requests |
| `auth_bypass` | Authenticating callers and connections |
| `authz_bypass` | Enforcing per-identity permission scopes |

## Scoring

**Agentic Score** = geometric_mean(Recall, 1 - Capability FP Rate, Mixed-Intent Accuracy)

- **Recall**: rewards real vulnerability detection
- **1 - Capability FP Rate**: rewards low noise on intentional capability code
- **Mixed-Intent Accuracy**: rewards correct boundary understanding inside one repo

## OWASP Agentic Top 10 Alignment

SASTbench cases are mapped to the [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as a reporting crosswalk. Each case carries a `standards.owaspAgenticTop10` field with primary and optional secondary ASI category labels. This mapping enables filtering and aggregating results by OWASP category without changing how the benchmark scores findings.

SASTbench currently has strong coverage for ASI02 (Tool Misuse & Exploitation), ASI03 (Identity & Privilege Abuse), and ASI05 (Unexpected Code Execution), plus targeted coverage for ASI01, ASI04, ASI06, and ASI07.

ASI08 (Cascading Failures), ASI09 (Human-Agent Trust Exploitation), and ASI10 (Rogue Agents) remain out of scope for the benchmark's current scoring model because they depend on system-level runtime behavior, human-in-the-loop evaluation, or long-horizon agent behavior rather than stable region-level SAST findings.

See [docs/OWASP_AGENTIC_TOP10_MAPPING.md](docs/OWASP_AGENTIC_TOP10_MAPPING.md) for the full mapping table and per-category case lists.

## Repository Layout

```text
sastbench/
|- manifest.json
|- schema/            # JSON schemas for cases and results
|- taxonomy/          # Canonical kinds, capabilities, languages
|- cases/
|  |- core/           # Synthetic vendored cases
|  `- full/           # Real-world disclosed cases
|- adapters/          # Scanner adapters (semgrep, bandit, etc.)
|- scripts/           # run, validate, report
`- tests/             # Benchmark self-tests
```

## License

TBD
