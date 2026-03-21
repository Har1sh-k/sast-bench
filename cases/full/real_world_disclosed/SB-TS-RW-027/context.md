# SB-TS-RW-027: n8n Webhook node IP whitelist bypass via substring includes() matching

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-w96v-gf22-crwp`
- CVE: `CVE-2025-68949`
- Vulnerable commit: `6ae4999ef99310d39c43cde611966875787b331b`
- Fix commit: `11f8597d4ad69ea3b58941573997fdbc4de1fec5`

## Scenario

n8n's Webhook node supports an IP whitelist feature that restricts which
source IP addresses are allowed to invoke a webhook. The whitelist
configuration accepts a comma-separated list of IP addresses or CIDR
ranges. The `isIpWhitelisted()` function in `utils.ts` is responsible for
checking whether an incoming request's IP address matches any entry in the
configured whitelist.

## Vulnerability

The `isIpWhitelisted()` function (lines 127-151 of `utils.ts`) uses
JavaScript's `String.includes()` method for IP address matching:

```typescript
for (const address of whitelist) {
    if (ip?.includes(address)) {
        return true;
    }

    if (ips.some((entry) => entry.includes(address))) {
        return true;
    }
}
```

The `includes()` method performs substring matching, not exact string
comparison. This creates two classes of bypass:

1. **Whitelist entry is a prefix of attacker IP**: If the whitelist
   contains `1.2.3.4`, an attacker from `1.2.3.40` or `1.2.3.4.evil.com`
   would not be blocked (though this direction is less exploitable with
   pure IP addresses).

2. **Attacker IP contains the whitelist entry as a substring**: If the
   whitelist contains `1.2.3.4`, the check `ip?.includes(address)` tests
   whether the IP string contains the whitelist entry. However, the
   arguments are reversed from what one might expect for a "contains"
   check -- it checks if the source IP includes the whitelist address as a
   substring. So `11.2.3.4` would pass because `'11.2.3.4'.includes('1.2.3.4')`
   is `true`.

Similarly, `192.168.1.3` would match a whitelist entry of `192.168.1.30`
because `'192.168.1.30'.includes('192.168.1.3')` is true (in the
`ips.some()` path where the check is on the entry side).

The fix replaces the substring matching with Node.js's `net.BlockList`
API, which provides proper IP address and CIDR range matching using
`blockList.check()`. This ensures exact address matching and correct
CIDR prefix evaluation.

## Source / Carrier / Sink
- Source: incoming HTTP request to the webhook endpoint from an IP address
  not intended to be in the whitelist
- Carrier: `isIpWhitelisted()` function that performs substring matching
  via `String.includes()` instead of exact or CIDR-aware IP comparison
- Sink: the webhook handler proceeds to process the request and trigger
  the workflow, treating the request as authorized
- Missing guard: exact IP comparison or CIDR-aware matching (e.g., using
  Node.js `net.BlockList` or equivalent) instead of substring matching

## Annotated Region
- File: `packages/nodes-base/nodes/Webhook/utils.ts`
- Lines: 127-151
- Why this region is the scoring target: it contains the entire
  `isIpWhitelisted()` function with the flawed `includes()` substring
  matching logic that allows IP whitelist bypass

## Scanner Expectation
A scanner should flag the `isIpWhitelisted()` function (lines 127-151 of
`utils.ts`) for using `String.includes()` to compare IP addresses against
a whitelist. Substring matching is not a valid IP comparison strategy and
allows bypass when an attacker's IP contains a whitelisted address as a
substring (e.g., `11.2.3.4` matching `1.2.3.4`).
