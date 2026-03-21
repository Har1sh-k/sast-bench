# SB-TS-RW-020: Local file disclosure via MEDIA: path validation accepting absolute and traversal paths

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-r8g4-86fx-92mq`
- CVE: `CVE-2026-25475`
- Vulnerable commit: `b17e6fdd07bcd2100946ae4042d3e3ebe5ef7b0f`
- Fix commit: `c67df653b64b439b48044f9545653d7b6c6f75e0`

## Scenario

OpenClaw's media subsystem processes `MEDIA:` tokens embedded in command output and chat text. When the system encounters a `MEDIA:` prefix followed by a path, it passes the path through `isValidMedia()` in `src/media/parse.ts` to determine whether the reference should be staged and delivered to the user. Valid media references are fetched from the filesystem and served through the media staging pipeline.

## Vulnerability

The `isValidMedia()` function (lines 17-27) validates candidate media paths by checking whether they match one of several accepted prefixes. While it correctly accepts HTTP(S) URLs and safe relative paths starting with `./`, it also accepts three dangerous path forms:

- Line 22: `if (candidate.startsWith("/")) return true;` -- accepts absolute filesystem paths such as `/etc/passwd` or `/etc/shadow`
- Line 24: `if (candidate.startsWith("../")) return true;` -- accepts parent directory traversal, allowing escape from the intended working directory
- Line 25: `if (candidate.startsWith("~")) return true;` -- accepts home-relative paths such as `~/.ssh/id_rsa` or `~/.aws/credentials`

An attacker who can influence text processed by the media parser (for example, by injecting `MEDIA:/etc/passwd` or `MEDIA:~/.ssh/id_rsa` into a message or command output) can cause the staging pipeline to read and deliver arbitrary local files.

The fix replaces all four local path checks (lines 22-25) with a single safe check: `return candidate.startsWith("./") && !candidate.includes("..");` -- only allowing relative paths under the current directory with no traversal.

## Source / Carrier / Sink
- Source: user-controlled or model-generated text containing `MEDIA:` tokens with attacker-chosen paths
- Carrier: `isValidMedia()` accepting absolute, traversal, and home-relative paths as valid media references
- Sink: the media staging pipeline reads the validated path from the local filesystem and delivers its contents
- Missing guard: path validation should restrict to safe relative paths only, rejecting absolute paths, `../` traversal, and `~` expansion

## Scanner Expectation
A scanner should flag the `isValidMedia()` function region in `src/media/parse.ts` (lines 17-27) where path validation accepts absolute paths (`/`), parent directory traversal (`../`), and home-relative paths (`~`) without sanitization. The vulnerability pattern is insufficient path validation in a file-access gate function, enabling path traversal to read arbitrary local files through the media staging pipeline.
