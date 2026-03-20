# SB-TS-RW-003: Inbound voice-call allowlist bypass via empty caller ID

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-4rj2-gpmh-qq5x`
- Vulnerable commit: `fc40ba8e7eb1345afdb1c8d274219cd702b73354`
- Fix commit: `f8dfd034f5d9235c5485f492a9e4ccc114e97fdb`

## Scenario

OpenClaw supports inbound voice calls with configurable access policies. When the `inboundPolicy` is set to `"allowlist"` or `"pairing"`, the `CallManager.shouldAcceptInbound` method validates the caller's phone number against a configured list of allowed numbers before accepting the call.

## Vulnerability

The `shouldAcceptInbound` method (lines 463-487 of `manager.ts`) normalizes the incoming caller ID by stripping non-digit characters (`from?.replace(/\D/g, "") || ""`). When the caller ID is missing or empty, the normalized value becomes an empty string `""`. The allowlist check then uses suffix matching: `normalized.endsWith(normalizedAllow) || normalizedAllow.endsWith(normalized)`. Since every string ends with the empty string (`"15550001234".endsWith("") === true`), an anonymous caller with no caller ID will match every entry in the allowlist. Additionally, the suffix matching itself is flawed: a number like `+99915550001234` would match allowlist entry `+15550001234` because the normalized allowlist value is a suffix of the caller's normalized number, enabling number-padding attacks.

## Source / Carrier / Sink
- Source: `event.from` field from the inbound call webhook, which may be absent or empty for anonymous callers
- Carrier: `shouldAcceptInbound` normalizes caller ID to an empty string when missing
- Sink: the `endsWith` comparison on line 480 returns `true` when either operand is empty, bypassing the allowlist
- Missing guard: no rejection of empty/missing caller IDs before the allowlist comparison; fix adds `normalizePhoneNumber` with an explicit empty-string rejection and switches to exact equality matching

## Scanner Expectation
A scanner should flag the allowlist validation logic in `shouldAcceptInbound` for using `endsWith`-based suffix matching that accepts empty strings, recognizing that a missing caller ID will bypass the entire allowlist check. The core issue is an authentication bypass where the empty-string case is not handled before comparison.
