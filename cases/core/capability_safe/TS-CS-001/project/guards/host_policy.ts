/**
 * Host policy guard — validates that outbound request URLs target
 * only pre-approved hosts from the static allowlist.
 */

import { APPROVED_HOSTS } from "../config/settings";

export class HostPolicyError extends Error {
  public readonly attemptedHost: string;

  constructor(host: string) {
    super(`Host not in allowlist: ${host}`);
    this.name = "HostPolicyError";
    this.attemptedHost = host;
  }
}

/**
 * Validate that a URL targets an approved host.
 *
 * The function parses the URL, extracts the hostname, and checks it
 * against the static allowlist defined in config/settings.ts. If the
 * host is not in the set, a HostPolicyError is thrown synchronously
 * before any network I/O occurs.
 *
 * @param rawUrl - The URL string to validate.
 * @throws {HostPolicyError} if the host is not in APPROVED_HOSTS.
 * @throws {TypeError} if the string is not a valid URL.
 */
export function enforceHostAllowlist(rawUrl: string): void {
  const parsed = new URL(rawUrl); // throws TypeError on malformed URL
  const host = parsed.hostname.toLowerCase();

  if (!APPROVED_HOSTS.has(host)) {
    throw new HostPolicyError(host);
  }
}
