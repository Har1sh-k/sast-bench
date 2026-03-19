/**
 * API client tool — makes outbound HTTP requests to ticketing / CRM APIs.
 *
 * SAFE: Every request is validated against the host allowlist defined in
 * guards/host_policy.ts before any network I/O occurs. Only URLs whose
 * hostname appears in the static APPROVED_HOSTS set are permitted.
 */

import { enforceHostAllowlist, HostPolicyError } from "../guards/host_policy";
import { REQUEST_TIMEOUT_MS, USER_AGENT } from "../config/settings";

export interface ApiResult {
  url: string;
  status: string;
  summary: string;
}

export async function callApi(url: string): Promise<ApiResult> {
  /**
   * Call an external API endpoint and return a summary of the response.
   *
   * Before issuing the HTTP request the URL is checked against the
   * host allowlist via enforceHostAllowlist(). If the host is not
   * approved, the request is rejected without opening a connection.
   */
  try {
    // --- guard: reject any host not on the static allowlist ---
    enforceHostAllowlist(url);

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const body = await response.json() as Record<string, unknown>;
    const summary = extractSummary(body);
    return {
      url,
      status: "ok",
      summary,
    };
  } catch (err: unknown) {
    if (err instanceof HostPolicyError) {
      return {
        url,
        status: "blocked",
        summary: `Request blocked: ${err.message}`,
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    return {
      url,
      status: "error",
      summary: message,
    };
  }
}

function extractSummary(json: Record<string, unknown>): string {
  /** Derive a one-line summary from a JSON API response. */
  if (typeof json.subject === "string") return json.subject;
  if (typeof json.title === "string") return json.title;
  if (typeof json.name === "string") return json.name;
  return JSON.stringify(json).slice(0, 120);
}
