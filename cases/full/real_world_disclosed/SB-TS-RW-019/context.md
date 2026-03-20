# SB-TS-RW-019: Command-authorized non-owners could reach owner-only /config and /debug surfaces

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-r7vr-gr74-94p8`
- Vulnerable commit: `fda49658183dc1afee48143f4de47dedc7590966`
- Fix commit: `08aa57a3de37d337b226ae861f573779f112ff2e`

## Scenario

OpenClaw's auto-reply system processes slash commands from chat messages. The `/config` and `/debug` commands allow reading and modifying the application's runtime configuration and debug overrides respectively. These commands pass through gate functions in `command-gates.ts` that check authorization before executing. The `commands-config.ts` file contains the `handleConfigCommand` and `handleDebugCommand` handler functions that wire together the gate checks and command logic.

## Vulnerability

Both `handleConfigCommand` (line 36) and `handleDebugCommand` (line 193) call `rejectUnauthorizedCommand` to verify the sender is an authorized command sender, but neither checks whether the sender is the owner. The `rejectUnauthorizedCommand` gate (in `command-gates.ts`) only checks `params.command.isAuthorizedSender`, which can be true for any user the owner has authorized to send commands -- not just the owner themselves. This means a non-owner authorized user can execute `/config set`, `/config unset`, `/config show`, and all `/debug` subcommands, gaining the ability to read sensitive configuration values, modify configuration on disk, and set runtime debug overrides that change application behavior.

The fix introduces a new `rejectNonOwnerCommand` gate function that checks `params.command.senderIsOwner` and wires it into both handlers. For `/config`, non-owner access is restricted to read-only `show` actions on internal channels. For `/debug`, all non-owner access is rejected.

## Source / Carrier / Sink
- Source: chat message from a non-owner but authorized sender invoking `/config` or `/debug` commands
- Carrier: `rejectUnauthorizedCommand` gate that checks authorization but not ownership
- Sink: `writeConfigFile` (for /config set/unset) and `setConfigOverride` (for /debug set) modify application state
- Missing guard: owner-level authorization check (`senderIsOwner`) before allowing config mutation and debug override operations

## Scanner Expectation
A scanner should flag the authorization gate region in `commands-config.ts` (lines 36-50) where `handleConfigCommand` checks `rejectUnauthorizedCommand` but lacks an owner-level check before proceeding to config mutation operations. The vulnerability pattern is an insufficient authorization granularity where "authorized to send commands" is conflated with "authorized to modify configuration", a classic horizontal privilege escalation in command dispatch.
