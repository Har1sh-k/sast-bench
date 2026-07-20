# USAF adapter

Runs JFrog USAF (`usaf_cli` / `usaf analyze`) and maps SARIF findings to SASTbench kinds.

## Required environment

| Variable | Meaning |
|----------|---------|
| `USAF_CLI` | Absolute path to `usaf_cli` (or `usaf`) |
| `USAF_RULES_JSON` | Absolute path to `dist/rules.json` from a usaf-rules checkout |
| `USAF_TIMEOUT` | Optional per-case timeout seconds (default `300`) |

## Supported languages

`python`, `typescript` (scanned as `javascript`), `javascript`, `rust`, `go`, `java`.

`swift` and `clojure` return `skipReason: language_not_supported`.

## Smoke

```bash
export USAF_CLI=/path/to/usaf_cli
export USAF_RULES_JSON=/path/to/usaf-rules/dist/rules.json
python scripts/run.py --scanner usaf --track core --case-id SB-PY-SV-001 --verbose
```
