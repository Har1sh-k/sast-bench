# SB-TS-RW-025: n8n Git node core.hooksPath RCE via model-controlled addConfig operation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-wpqc-h9wp-chmq`
- CVE: `CVE-2025-65964`
- Vulnerable commit: `53fd5c94c8798292cc981508a937b09532bbcf64`
- Fix commit: `d5a1171f95f75def5c3ac577707ab913e22aef04`

## Scenario

n8n's Git node provides various Git operations including "Add Config" which
allows setting arbitrary Git configuration properties. When the node is
used as a tool (it has `usableAsTool: true`), an AI agent or workflow author
can control the key and value parameters passed to the addConfig operation.

## Vulnerability

The `addConfig` operation handler (lines 333-354 of `Git.node.ts`) reads
the `key` and `value` parameters from user/model input and passes them
directly to `git.addConfig(key, value, append)` without any validation or
restriction on which configuration keys are allowed.

An attacker can exploit this by:
1. Cloning a malicious repository that contains a hook script (e.g.,
   `.git/hooks/post-checkout` or a custom hooks directory)
2. Using the "Add Config" operation to set `core.hooksPath` pointing to
   a directory within the cloned repo that contains executable hook scripts
3. Triggering a subsequent Git operation (e.g., commit, checkout) that
   invokes the hook, executing arbitrary code on the n8n server

The vulnerable code path:
```typescript
const key = this.getNodeParameter('key', itemIndex, '') as string;
const value = this.getNodeParameter('value', itemIndex, '') as string;
// ...
await git.addConfig(key, value, append);
```

No allowlist or blocklist is applied to the `key` parameter. The
`core.hooksPath` configuration directive tells Git to use an alternative
directory for hooks, bypassing the default `.git/hooks` directory.

The fix adds a global configuration override `core.hooksPath=/dev/null`
that is applied whenever `enableGitNodeHooks` is false (the default),
which neutralizes any attempt to set a custom hooks path.

## Source / Carrier / Sink
- Source: `key` and `value` node parameters controlled by user or AI agent
  input via `this.getNodeParameter('key', ...)` and
  `this.getNodeParameter('value', ...)`
- Carrier: the addConfig operation handler that blindly forwards these
  parameters without validation
- Sink: `git.addConfig(key, value, append)` at line 346 which writes
  arbitrary Git configuration, including `core.hooksPath`
- Missing guard: no validation or allowlist on the configuration key
  parameter; no default override to disable hooks execution

## Annotated Region
- File: `packages/nodes-base/nodes/Git/Git.node.ts`
- Lines: 333-354
- Why this region is the scoring target: it contains the `addConfig`
  operation handler that passes unsanitized user input to
  `git.addConfig()`, enabling `core.hooksPath` injection for RCE

## Scanner Expectation
A scanner should flag the `addConfig` operation handler (lines 333-354)
for passing user-controlled input to `git.addConfig()` without validating
the configuration key. The `core.hooksPath` key allows redirecting Git
hooks execution to an attacker-controlled directory, achieving arbitrary
code execution.
