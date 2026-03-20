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
python scripts/report.py results/
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

## OWASP Agentic Security Top 10 Alignment

SASTbench cases are mapped to the [OWASP Top 10 for Agentic Security](https://owasp.org/www-project-top-10-for-agentic-security/) as a reporting crosswalk.  Each case carries an optional `standards.owaspAgenticTop10` field with primary and secondary ASI category labels.  This mapping enables filtering and aggregating results by OWASP category without changing how the benchmark scores findings.

SASTbench currently covers ASI01 through ASI07.  ASI08 (Inadequate Error Handling), ASI09 (Insufficient Logging), and ASI10 (Resource Exhaustion) are out of scope for static analysis benchmarks.

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
