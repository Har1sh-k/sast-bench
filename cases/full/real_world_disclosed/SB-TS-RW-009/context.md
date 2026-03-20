# SB-TS-RW-009: LINE group allowlist scope mismatch with DM pairing-store entries

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-gp3q-wpq4-5c5h`
- Vulnerable commit: `fe92113472e9d80da7dacf671aba0e5a41ce1295`
- Fix commit: `dbccc73d7a1b6681c96c1f513ca42646755a0cae`

## Scenario

OpenClaw provides a LINE messaging channel integration with configurable access policies. Group messages can be restricted via a `groupAllowFrom` allowlist that controls which senders may trigger bot processing in group chats. Separately, a DM pairing flow lets individual users pair with the bot, storing their identity in a pairing store. The `shouldProcessLineEvent` function in `bot-handlers.ts` resolves the effective allowlist for both DM and group contexts.

## Vulnerability

When no explicit `groupAllowFrom` is configured, the code falls back to `account.config.allowFrom` via the `fallbackGroupAllowFrom` variable (lines 157-159). This base `allowFrom` list is populated from the DM pairing store, meaning any user who completed DM pairing is implicitly authorized to send messages in all groups. The `effectiveGroupAllow` computed at line 167 therefore includes DM-paired identities that were never explicitly granted group access. An attacker who pairs with the bot in a DM automatically gains the ability to trigger bot processing in any LINE group the bot belongs to, bypassing the intended group-level authorization boundary.

## Source / Carrier / Sink
- Source: DM pairing-store entries loaded via `readChannelAllowFromStore` and merged into `account.config.allowFrom`
- Carrier: `fallbackGroupAllowFrom` variable that inherits DM-scoped identities into the group allowlist resolution at lines 157-164
- Sink: `effectiveGroupAllow` at line 167 which is used for group sender authorization checks, granting DM-paired users group access
- Missing guard: group allowlist resolution should not fall back to DM pairing-store entries; group and DM authorization scopes must be kept separate

## Scanner Expectation
A scanner should flag the group allowlist fallback logic where `fallbackGroupAllowFrom` inherits from `account.config.allowFrom` (which includes DM pairing-store identities) and feeds into `effectiveGroupAllow`, creating an authorization scope mismatch that allows DM-paired users to bypass group-level access controls.
