# SASTbench Adapters

Each adapter lives in its own directory and implements a Python module
named `adapter.py` with two required functions:

## Required Interface

```python
def get_version() -> str:
    """Return the scanner version string."""
    ...

def scan(scan_root: Path, language: str) -> list[dict]:
    """Run the scanner and return normalized findings.

    Each finding dict must have:
      - ruleId: str       - original scanner rule ID
      - mappedKind: str   - canonical kind (command_injection, path_traversal, ssrf, unmapped)
      - path: str         - file path relative to scan_root
      - startLine: int    - first line of the finding
      - endLine: int      - last line of the finding

    Optional fields:
      - severity: str     - low, medium, high, critical
      - message: str      - scanner-reported message
    """
    ...
```

Official adapters should also expose:

```python
def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Return findings plus raw stdout/stderr and command metadata."""
    ...
```

`scan_with_metadata()` is what lets the benchmark preserve raw scanner
output for auditing and link to those artifacts from reports.

## Official Adapters

| Adapter | Scanner | Languages |
|---------|---------|-----------|
| `semgrep/` | Semgrep | Python, TypeScript, Rust |
| `bandit/` | Bandit | Python only |

These are the only baseline adapters intended for official leaderboard runs today.

## Experimental Adapters

- `xfire/`
- `securevibes/`
- `securevibes-agent/`

Experimental adapters are useful for local comparison work, but they are not part of the official baseline until they meet the same reproducibility and path-plus-line fidelity requirements as the baseline adapters.

## Adding a New Adapter

1. Create a directory under `adapters/` with the scanner name
2. Add an `adapter.py` implementing `get_version()` and `scan()`
3. Map scanner rules to canonical kinds in a `RULE_KIND_MAP` dict
4. Test with: `python scripts/run.py --scanner <name> --track core`
