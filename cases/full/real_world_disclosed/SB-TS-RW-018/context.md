# SB-TS-RW-018: Workspace plugin auto-discovery allowed code execution from cloned repositories

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-99qw-6mr3-36qr`
- Vulnerable commit: `0a8fa0e0010379813fd090e013c0eb268916f342`
- Fix commit: `3e28e10c2f3cbe81d295a553fb2909905152cb09`

## Scenario

OpenClaw supports a plugin system where plugins can originate from different sources: bundled (shipped with the application), configured (explicitly loaded via config), and workspace (discovered from repository directories). The `resolveEnableState` function in `src/plugins/config-state.ts` determines whether a given plugin should be enabled based on its origin, the allow/deny lists, explicit config entries, and defaults.

## Vulnerability

The `resolveEnableState` function (lines 197-225) has a permissive default for workspace-origin plugins. When a plugin is not on the deny list, not explicitly disabled in config entries, not blocked by the allowlist, and not a bundled plugin, the function falls through to a final `return { enabled: true }` at line 224. This means workspace plugins discovered from cloned repository directories are auto-enabled by default. An attacker who controls a repository that a user clones can embed a malicious plugin in the workspace directory structure. When OpenClaw processes that repository, the plugin will be automatically discovered and loaded, achieving arbitrary code execution in the user's environment without any explicit opt-in or confirmation.

The fix adds an explicit check for workspace-origin plugins: `if (origin === "workspace" && !explicitlyAllowed && entry?.enabled !== true)` that returns `{ enabled: false, reason: "workspace plugin (disabled by default)" }`, requiring workspace plugins to be explicitly allowed before they can execute.

## Source / Carrier / Sink
- Source: plugin files placed in a cloned repository's workspace directory by an attacker
- Carrier: plugin discovery mechanism that assigns `origin: "workspace"` to repository-local plugins
- Sink: `resolveEnableState` returns `{ enabled: true }` for workspace plugins, leading to plugin loading and code execution
- Missing guard: workspace-origin plugins should be disabled by default and require explicit user opt-in via allowlist or config

## Scanner Expectation
A scanner should flag the `resolveEnableState` function (lines 197-225) for its permissive default that auto-enables workspace-origin plugins. The vulnerability pattern is an insufficient trust boundary where externally-sourced code (from cloned repositories) is treated with the same trust level as bundled or user-configured plugins, leading to automatic code execution from untrusted sources.
