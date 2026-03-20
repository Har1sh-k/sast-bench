# TS-SV-003: Plugin-Extensible Agent — Unverified Remote Code Execution

## Scenario

A plugin-extensible agent loads extensions at startup from a configurable
registry URL. The plugin loader fetches a manifest JSON from the registry,
iterates over declared plugins, downloads each plugin's code from the URL
specified in the manifest, and evaluates it using `eval()` to register the
plugin. There is no integrity verification: no hash check, no digital
signature validation, and no allowlist of trusted sources.

## Vulnerability

The `plugin-loader.ts` module fetches plugin code from URLs specified in an
untrusted registry manifest and passes the downloaded code directly to
`eval()`. A compromised registry, a man-in-the-middle attacker, or a
malicious manifest entry can cause the agent to execute arbitrary code.

## Why this is vulnerable

- **Source**: Remote registry manifest (untrusted URL providing plugin code URLs)
- **Carrier**: Registry client fetches manifest; plugin loader iterates entries
- **Sink**: `eval(code)` in `plugin-loader.ts`
- **Missing guard**: No hash verification, no code signing, no source allowlist

## What a scanner should find

A finding on `plugin-loader.ts` lines 25-68 indicating that code fetched
from an untrusted remote source is passed to `eval()` without integrity
verification, enabling arbitrary code execution.
