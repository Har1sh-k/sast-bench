/** Agent configuration constants. */

/** Strict allowlist of approved API hosts for customer support operations. */
export const APPROVED_HOSTS: ReadonlySet<string> = new Set([
  "api.zendesk.com",
  "api.salesforce.com",
  "api.freshdesk.com",
  "api.hubspot.com",
]);

/** Default timeout for outbound API requests. */
export const REQUEST_TIMEOUT_MS = 8_000;

/** Maximum number of API calls per plan execution. */
export const MAX_API_CALLS = 10;

/** User-Agent header sent with every outbound request. */
export const USER_AGENT = "CustomerSupportAgent/1.0";
