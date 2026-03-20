# SB-TS-RW-005: ACPX Windows wrapper shell fallback allowed cwd injection

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-6f6j-wx9w-ff4j`
- Vulnerable commit: `13bb80df9d202285aeec94ea30f70e34d4131dce`
- Fix commit: `9e6e7a3d69958da000df3690c7cbb186bb1825e8`

## Scenario

OpenClaw's ACPX (Agent Capability Protocol Extension) runtime spawns external tool processes on behalf of agents. On Windows, npm-installed CLI tools are typically exposed as `.cmd` wrapper scripts that invoke the underlying Node.js entry point. The `resolveSpawnCommand` function in `process.ts` determines how to execute a given command, with special handling for Windows platforms where certain file extensions require different spawn strategies.

## Vulnerability

The `resolveSpawnCommand` function (lines 17-40) checks if the command has a `.cmd` or `.bat` extension and, if so, sets `shell: true` to spawn it through `cmd.exe`. This is the only path resolution it performs for wrapper files -- it does not attempt to read the wrapper content, resolve the underlying executable, or look up bare command names via PATH/PATHEXT. When `shell: true` is used, the `cwd` parameter and any arguments are subject to cmd.exe shell parsing, which interprets metacharacters like `&`, `|`, `>`, and `^`. Since the `cwd` value passed to `spawnWithResolvedCommand` can originate from model-controlled inputs, an attacker-controlled cwd containing shell metacharacters (e.g., `C:\safe & calc`) would be parsed by cmd.exe, enabling arbitrary command injection. Additionally, bare command names (without a path or extension) are passed through unresolved, meaning they may silently resolve to `.cmd` wrappers on Windows that the function cannot inspect for safe unwrapping.

## Source / Carrier / Sink
- Source: model-controlled `command` and `cwd` parameters passed to `spawnWithResolvedCommand`
- Carrier: `resolveSpawnCommand` sets `shell: true` for `.cmd`/`.bat` wrappers without unwrapping the shim to its safe underlying executable
- Sink: `spawn()` with `shell: true` passes arguments and cwd through cmd.exe, which interprets shell metacharacters
- Missing guard: the fix resolves `.cmd` wrappers via PATH/PATHEXT, reads the wrapper content to extract the underlying Node.js or EXE entrypoint, and spawns the unwrapped executable directly without shell parsing where possible

## Scanner Expectation
A scanner should flag the `shell: true` spawn path for `.cmd`/`.bat` files as a command injection vector, recognizing that model-controlled arguments or working directories are processed by the system shell without sanitization. The function should be identified as blindly delegating to cmd.exe without attempting to resolve a safe, shell-free execution path.
