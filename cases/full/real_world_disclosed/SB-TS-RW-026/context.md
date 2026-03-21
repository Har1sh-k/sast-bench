# SB-TS-RW-026: n8n Stripe Trigger webhook forgery via missing signature verification

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-jf52-3f2h-h9j5`
- CVE: `CVE-2026-21894`
- Vulnerable commit: `8f4b84fdd3b316dffe7d9e37c13f94fc99718c39`
- Fix commit: `a61a5991093c41863506888336e808ac1eff8d59`

## Scenario

n8n's Stripe Trigger node registers a webhook endpoint with Stripe and
listens for incoming event notifications. When Stripe creates the webhook,
it returns a signing secret (`responseData.secret`) which is stored in the
node's workflow static data at `webhookData.webhookSecret` (line 919). This
secret is intended to be used for verifying that incoming requests genuinely
originate from Stripe via HMAC-SHA256 signature verification of the
`Stripe-Signature` header.

## Vulnerability

The `webhook()` method (lines 948-966) processes incoming webhook requests
by extracting the body data and checking whether the event type matches the
configured event filter. However, it never reads the `Stripe-Signature`
header and never verifies the request payload against the stored
`webhookSecret`.

The vulnerable webhook handler:
```typescript
async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const bodyData = this.getBodyData();
    const req = this.getRequestObject();
    const events = this.getNodeParameter('events', []) as string[];
    const eventType = bodyData.type as string | undefined;

    if (eventType === undefined || (!events.includes('*') && !events.includes(eventType))) {
        return {};
    }

    return {
        workflowData: [this.helpers.returnJsonArray(req.body as IDataObject)],
    };
}
```

Any HTTP client that knows or discovers the webhook URL can send a forged
POST request with an arbitrary JSON body containing a valid event type, and
the node will accept it and trigger the downstream workflow. This enables:

- Triggering workflows with fabricated payment events
- Injecting fake refund, dispute, or subscription events
- Manipulating business logic that depends on Stripe webhook data

The fix introduces a `verifySignature()` helper that implements
HMAC-SHA256 verification of the `Stripe-Signature` header, validates the
timestamp within a 5-minute tolerance window, and uses timing-safe
comparison. The webhook handler calls this verification before processing
the event, returning 401 Unauthorized on failure.

## Source / Carrier / Sink
- Source: unauthenticated HTTP POST request to the webhook URL with a
  crafted JSON body containing a Stripe event structure
- Carrier: the `webhook()` method that reads `this.getBodyData()` without
  any signature verification step
- Sink: `this.helpers.returnJsonArray(req.body)` at line 963 passes the
  unverified payload into the workflow as trusted data
- Missing guard: HMAC-SHA256 signature verification of the
  `Stripe-Signature` header against the stored `webhookData.webhookSecret`

## Annotated Region
- File: `packages/nodes-base/nodes/Stripe/StripeTrigger.node.ts`
- Lines: 948-966
- Why this region is the scoring target: it contains the entire `webhook()`
  method that accepts and processes incoming Stripe webhook payloads without
  performing any signature verification, despite the signing secret being
  available in the node's static data

## Scanner Expectation
A scanner should flag the `webhook()` method (lines 948-966 of
`StripeTrigger.node.ts`) for processing webhook payloads without verifying
the `Stripe-Signature` header. The signing secret is stored during webhook
creation (line 919) but never referenced in the webhook handler, making it
trivial for an attacker to forge Stripe events.
