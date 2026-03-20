# SB-TS-RW-012: Plugin installation accepted traversal-like package names escaping extensions dir

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-qrq5-wjgg-rvqw`
- Vulnerable commit: `be9a2fb134182a4197d65989bbfaa7f54d6d3ae6`
- Fix commit: `d03eca8450dc493b198a88b105fd180895238e57`

## Scenario

OpenClaw supports a plugin/extension system where plugins are installed from archives, directories, or npm packages into a dedicated extensions directory. The `installPluginFromPackageDir` function reads the plugin's `package.json` to extract the package name, derives a `pluginId` via `unscopedPackageName`, and computes the target installation directory via `safeDirName`. The intent is that all plugins are installed as subdirectories under the configured extensions directory.

## Vulnerability

The `unscopedPackageName` function (line 39-45) strips npm scope prefixes by splitting on `/` and taking the last segment. For a package named `@evil/..`, this yields `..` as the pluginId. The `safeDirName` function (lines 47-53) only replaces forward slashes with double underscores, but `..` contains no slashes and passes through unchanged. It also does not handle backslashes on Windows. When `path.join(extensionsDir, '..')` is computed at line 125, the result escapes the extensions directory entirely. The attacker's plugin files are then copied via `fs.cp` to the parent directory, allowing arbitrary file writes outside the intended sandbox. The fix adds a `validatePluginId` function that rejects reserved path segments (`.`, `..`) and path separators, plus a `resolveSafeInstallDir` function that performs a resolved-path containment check.

## Source / Carrier / Sink
- Source: attacker-controlled `package.json` `name` field (e.g., `@evil/..`) in a malicious plugin archive
- Carrier: `unscopedPackageName` extracts `..` as the pluginId, and `safeDirName` passes it through without blocking traversal segments
- Sink: `path.join(extensionsDir, safeDirName(pluginId))` at line 125 computes a target directory outside the extensions sandbox, and `fs.cp` writes attacker-controlled files there
- Missing guard: validation that the pluginId is not a reserved path segment and that the resolved target directory is contained within the extensions base directory

## Scanner Expectation
A scanner should flag the `unscopedPackageName` and `safeDirName` functions for insufficient input validation, allowing path traversal segments like `..` to pass through and escape the intended extensions directory when used in `path.join` to compute the installation target.
