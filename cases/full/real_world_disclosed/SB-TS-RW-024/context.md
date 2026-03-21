# SB-TS-RW-024: Authorization bypass via spoofed x-request-from header in API middleware

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-wvhq-wp8g-c7vq`
- CVE: `CVE-2026-30820`
- Vulnerable commit: `ae987069440b102cf76a0542c536acbb10f3b3fe`
- Fix commit: `8ce06c72017c271bbc7990784c27710d49599f6b`
- Patched in: flowise@3.0.13

## Scenario

Flowise's Express server uses a global middleware to protect all `/api/v1` routes. The middleware distinguishes between three authentication paths: whitelisted URLs pass through freely, requests with the `x-request-from: internal` header are authenticated via session token only, and all other requests must provide a valid API key with associated workspace and organization context.

## Vulnerability

The authentication middleware in `index.ts` (lines 215-280) contains a three-branch authorization check:

```typescript
if (isWhitelisted) {
    next();
} else if (req.headers['x-request-from'] === 'internal') {
    verifyToken(req, res, next);
} else {
    const { isValid, apiKey } = await validateAPIKey(req);
    // ... full API key + workspace + org validation
}
```

The `x-request-from` header on line 224 is a client-supplied HTTP header that any external client can set. When this header equals `'internal'`, the middleware calls only `verifyToken()` which validates the session JWT cookie but does not perform API key validation, workspace authorization, organization checks, or endpoint-level permission enforcement.

Any authenticated tenant who has a valid UI session cookie can add `x-request-from: internal` to their requests to bypass the full API key authorization path. This grants access to internal administration endpoints including `/api/v1/apikey` (API key management), `/api/v1/credentials` (stored secrets), `/api/v1/tools` (tool configuration), and `/api/v1/node-custom-function` (arbitrary code execution), effectively escalating from a low-privilege tenant to full administrative access.

The fix adds an `API_KEY_BLACKLIST_URLS` list that blocks sensitive endpoints from API key access, restricting what can be reached even through the internal header path.

## Source / Carrier / Sink
- Source: `req.headers['x-request-from']` header at line 224, a client-controlled HTTP header that any external request can set
- Carrier: the conditional branch in the authentication middleware that short-circuits to `verifyToken()` instead of the full `validateAPIKey()` path
- Sink: `next()` is called after only session token verification, allowing the request to proceed to any downstream `/api/v1` route handler including administrative endpoints
- Missing guard: no validation that the `x-request-from` header originates from a trusted source; no endpoint-level authorization after the session token check; no restriction on which routes the internal path can access

## Annotated Region
- File: `packages/server/src/index.ts`
- Lines: 215-280
- Why this region is the scoring target: it contains the global authentication middleware where the spoofable `x-request-from` header determines the authorization path, allowing session-authenticated users to bypass API key checks and access all protected endpoints

## Scanner Expectation
A scanner should flag the `req.headers['x-request-from'] === 'internal'` check at line 224 for trusting a client-controlled header to make authorization decisions. The vulnerability pattern is an authentication bypass where a spoofable request header short-circuits the full authorization flow, granting elevated access to any authenticated session holder.
