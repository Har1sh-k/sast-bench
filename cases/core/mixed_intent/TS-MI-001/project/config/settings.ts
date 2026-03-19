/** Browser assistant configuration. */

/**
 * Domains pre-approved by the security team for navigation.
 * The assistant may only browse pages on these hosts.
 */
export const APPROVED_DOMAINS: readonly string[] = [
  "www.amazon.com",
  "www.bestbuy.com",
  "www.target.com",
  "www.walmart.com",
  "www.yelp.com",
  "www.tripadvisor.com",
  "www.google.com",
];

/** General settings */
export const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_BODY_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
export const USER_AGENT = "ConsumerBrowserAssistant/1.0";
