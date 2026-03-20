# SB-TS-RW-004: Gateway plugin auth bypass via encoded dot-segment traversal

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-mwxv-35wr-4vvj`
- Vulnerable commit: `44270c533b09e8d7e87fbeecc0b1c69a6ee98452`
- Fix commit: `93b07240257919f770d1e263e1f22753937b80ea`

## Scenario

OpenClaw's gateway server protects certain HTTP plugin routes (under `/api/channels/`) with authentication checks. Before dispatching requests to plugin handlers, the gateway canonicalizes the request path by decoding percent-encoded sequences and resolving dot-segments, then checks if the canonical path matches any protected prefix. If it does, the request must pass gateway authentication before being forwarded.

## Vulnerability

The `buildCanonicalPathCandidates` function (lines 43-68 of `security-path.ts`) iterates up to `MAX_PATH_DECODE_PASSES` (set to 3) decoding rounds. An attacker can defeat the canonicalization by encoding the path with 4 or more levels of percent-encoding. For example, quadruple-encoding `/api/channels/nostr/default/profile` produces a path like `/api%2525252fchannels%2525252fnostr%2525252fdefault%2525252fprofile`. After only 3 decode rounds the path still contains encoded slashes and does not match the `/api/channels` protected prefix, so the request bypasses gateway authentication. Critically, the function does not detect that decoding is still incomplete after exhausting the pass limit -- it simply returns whatever candidates it has accumulated, failing open. The plugin HTTP handler then receives the request and decodes the remaining encoding itself, routing it to the protected channel endpoint without authentication.

## Source / Carrier / Sink
- Source: attacker-controlled HTTP request path with deeply nested percent-encoding
- Carrier: `buildCanonicalPathCandidates` with a fixed decode pass limit of 3 that fails open when the limit is exhausted
- Sink: `isPathProtectedByPrefixes` returns `false` for paths that are still partially encoded, allowing unauthenticated access to protected plugin routes
- Missing guard: the function does not check whether decoding has converged to a fixpoint after the loop; fix increases the limit to 32 and adds `decodePassLimitReached` detection with fail-closed behavior

## Scanner Expectation
A scanner should flag the bounded decode loop in `buildCanonicalPathCandidates` for failing open when the decode pass limit is exhausted. The key vulnerability is that `MAX_PATH_DECODE_PASSES = 3` is insufficient to fully decode deeply encoded paths, and the function does not detect or handle the case where decoding is incomplete, allowing authentication bypass on protected route prefix checks.
