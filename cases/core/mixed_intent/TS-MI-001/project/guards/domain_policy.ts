/**
 * Domain-allowlist guard for outbound navigation requests.
 *
 * This module enforces that a URL's hostname is present in an explicit
 * allowlist before any network I/O occurs.  It is the primary mitigation
 * against SSRF in the navigation path.
 */

import { APPROVED_DOMAINS } from "../config/settings";

export class DomainNotAllowedError extends Error {
  constructor(hostname: string) {
    super(
      `Host '${hostname}' is not in the approved domain allowlist. ` +
        `Allowed domains: ${APPROVED_DOMAINS.join(", ")}`
    );
    this.name = "DomainNotAllowedError";
  }
}

export interface PolicyVerdict {
  readonly allowed: boolean;
  readonly url: string;
  readonly reason: string;
}

/**
 * Validate that the given URL targets an approved domain.
 *
 * Checks both the scheme (must be http or https) and the hostname
 * (must appear in the static allowlist).  Returns a verdict describing
 * whether the URL is permitted for navigation.
 */
export function enforceDomainPolicy(url: string): PolicyVerdict {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return {
      allowed: false,
      url,
      reason: `Invalid URL: ${url}`,
    };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      allowed: false,
      url,
      reason: `Unsupported scheme '${parsed.protocol}' in URL: ${url}`,
    };
  }

  if (!parsed.hostname) {
    return {
      allowed: false,
      url,
      reason: `URL has no hostname: ${url}`,
    };
  }

  const isApproved = APPROVED_DOMAINS.includes(parsed.hostname);
  if (!isApproved) {
    return {
      allowed: false,
      url,
      reason:
        `Host '${parsed.hostname}' is not in the approved domain allowlist. ` +
        `Allowed: [${APPROVED_DOMAINS.join(", ")}]`,
    };
  }

  return {
    allowed: true,
    url,
    reason: `Host '${parsed.hostname}' matches approved domain`,
  };
}
