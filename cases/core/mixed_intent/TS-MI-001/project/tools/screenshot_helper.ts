/**
 * Screenshot / preview helper — fetches a URL to generate a visual preview.
 *
 * VULNERABLE: This tool accepts arbitrary URLs from the agent planner
 * without enforcing a host allowlist or scheme restriction.  Unlike the
 * navigator tool, it was added as a quick utility and never received the
 * same domain-policy guard.
 */

import { REQUEST_TIMEOUT_MS, USER_AGENT } from "../config/settings";

export interface PreviewResult {
  url: string;
  status: "ok" | "error";
  contentType: string;
  bodyLength: number;
  snippet: string;
}

/**
 * Fetch a URL for screenshot / preview purposes.
 *
 * This function receives URLs directly from the agent planner, which
 * are ultimately sourced from model output.  There is no validation on
 * the target host or URL scheme before the request is made.
 *
 * A host allowlist (identical to the one used in `navigator.ts`) would
 * prevent SSRF here but is missing.
 */
export async function fetchPreview(url: string): Promise<PreviewResult> {
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html, image/*, */*",
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const contentType = response.headers.get("content-type") ?? "unknown";
    const body = await response.text();

    return {
      url,
      status: "ok",
      contentType,
      bodyLength: body.length,
      snippet: body.slice(0, 200),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      url,
      status: "error",
      contentType: "",
      bodyLength: 0,
      snippet: message,
    };
  }
}
