/**
 * URL fetcher tool — retrieves content from a URL.
 *
 * VULNERABLE: This tool accepts arbitrary URLs from the agent planner
 * without enforcing a host allowlist or scheme restriction.
 */

import { REQUEST_TIMEOUT_MS, USER_AGENT } from "../config/settings";

export interface FetchResult {
  url: string;
  status: string;
  title: string;
}

export async function fetchUrl(url: string): Promise<FetchResult> {   // line 15
  /**
   * Fetch a URL and return page metadata.
   *
   * This function receives URLs directly from the agent planner, which
   * are ultimately sourced from model output. There is no validation on
   * the target host or URL scheme before the request is made.
   *
   * A host allowlist (e.g., restricting to api.booking.com,
   * api.skyscanner.net, api.openweathermap.org) would prevent SSRF
   * here but is missing.
   */
  try {
    const response = await fetch(url, {                               // line 28
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const body = await response.text();
    const title = extractTitle(body);
    return {
      url,
      status: "ok",
      title,
    };                                                                // line 43
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      url,
      status: "error",
      title: message,
    };
  }
}

function extractTitle(html: string): string {
  /** Extract a rough title from HTML content. */
  const start = html.indexOf("<title>");
  const end = html.indexOf("</title>");
  if (start !== -1 && end !== -1) {
    return html.slice(start + 7, end).trim();
  }
  return "Untitled";
}
