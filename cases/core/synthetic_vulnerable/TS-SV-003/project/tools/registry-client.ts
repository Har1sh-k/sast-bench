/**
 * Registry client — fetches plugin manifests from a remote registry.
 *
 * This module is responsible for HTTP communication with the plugin
 * registry. It fetches and validates the manifest structure but does
 * NOT download or execute plugin code itself.
 */

import { REGISTRY_URL, FETCH_TIMEOUT_MS } from "../config/settings";

export interface PluginManifestEntry {
  name: string;
  version: string;
  codeUrl: string;
  description: string;
}

export interface PluginManifest {
  schemaVersion: string;
  plugins: PluginManifestEntry[];
}

/**
 * Fetch the plugin manifest from the configured registry.
 *
 * Validates that the response is well-formed JSON with the expected
 * structure. Throws on network errors or malformed responses.
 */
export async function fetchManifest(): Promise<PluginManifest> {
  const url = `${REGISTRY_URL}/manifest.json`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, { signal: controller.signal });

    if (!response.ok) {
      throw new Error(
        `Registry returned HTTP ${response.status}: ${response.statusText}`,
      );
    }

    const data: unknown = await response.json();

    if (!isValidManifest(data)) {
      throw new Error("Registry manifest has invalid structure");
    }

    return data;
  } finally {
    clearTimeout(timeoutId);
  }
}

function isValidManifest(data: unknown): data is PluginManifest {
  if (typeof data !== "object" || data === null) return false;
  const obj = data as Record<string, unknown>;
  if (typeof obj.schemaVersion !== "string") return false;
  if (!Array.isArray(obj.plugins)) return false;
  return obj.plugins.every(
    (p: unknown) =>
      typeof p === "object" &&
      p !== null &&
      typeof (p as Record<string, unknown>).name === "string" &&
      typeof (p as Record<string, unknown>).version === "string" &&
      typeof (p as Record<string, unknown>).codeUrl === "string",
  );
}
