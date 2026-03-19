/**
 * Navigation tool — opens a URL and returns page content.
 *
 * SAFE: This tool enforces a strict domain allowlist before making any
 * outbound request.  Only pre-approved shopping and review domains are
 * permitted.  The domain policy guard rejects all other hosts, preventing
 * SSRF even if the LLM planner suggests a malicious URL.
 */

import { enforceDomainPolicy } from "../guards/domain_policy";
import { REQUEST_TIMEOUT_MS, USER_AGENT } from "../config/settings";

export interface NavigationResult {
  url: string;
  status: "ok" | "blocked" | "error";
  title: string;
  bodySnippet: string;
}

/**
 * Navigate to a URL after verifying it against the domain allowlist.
 *
 * The planner supplies URLs derived from model output.  Before any network
 * I/O, this function calls `enforceDomainPolicy` to confirm the target host
 * is on the approved list.  If the host is not approved, the request is
 * rejected without ever opening a connection.
 */
export async function navigateTo(url: string): Promise<NavigationResult> {
  // --- guard: domain allowlist ---
  const verdict = enforceDomainPolicy(url);
  if (!verdict.allowed) {
    return {
      url,
      status: "blocked",
      title: "Navigation blocked",
      bodySnippet: verdict.reason,
    };
  }

  // --- guarded fetch ---
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": USER_AGENT },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const body = await response.text();
    const title = extractTitle(body);
    const bodySnippet = body.slice(0, 500);

    return { url, status: "ok", title, bodySnippet };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { url, status: "error", title: message, bodySnippet: "" };
  }
}

function extractTitle(html: string): string {
  const start = html.indexOf("<title>");
  const end = html.indexOf("</title>");
  if (start !== -1 && end !== -1) {
    return html.slice(start + 7, end).trim();
  }
  return "Untitled";
}
