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

- Core Track is implemented and validated.
- Full Track now includes 6 `real_world_disclosed` cases and exceeds the
  minimum `v1.0.0` release bar.
- `v1.0.0` still targets 5 to 10+ real-world cases if they annotate cleanly.

## Official Adapters

- `semgrep`
- `bandit`

## V1 Canonical Vulnerability Kinds

| Kind | Capability Surface |
|------|--------------------|
| `command_injection` | Executing commands |
| `path_traversal` | Reading and writing files |
| `ssrf` | Making outbound network requests |

## Scoring

**Agentic Score** = geometric_mean(Recall, 1 - Capability FP Rate, Mixed-Intent Accuracy)

- **Recall**: rewards real vulnerability detection
- **1 - Capability FP Rate**: rewards low noise on intentional capability code
- **Mixed-Intent Accuracy**: rewards correct boundary understanding inside one repo

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
