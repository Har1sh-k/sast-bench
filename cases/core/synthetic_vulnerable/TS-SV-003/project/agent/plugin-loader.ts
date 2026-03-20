/**
 * Plugin loader — downloads and executes plugin code from the registry.
 *
 * VULNERABLE: This module fetches plugin code from URLs declared in a
 * remote manifest and passes it directly to eval() without any integrity
 * verification. There is no hash check, no signature validation, and no
 * source allowlist enforcement. A compromised registry or MITM attacker
 * can cause execution of arbitrary code.
 */

import {
  fetchManifest,
  PluginManifestEntry,
} from "../tools/registry-client";
import { FETCH_TIMEOUT_MS, MAX_PLUGIN_SIZE_BYTES } from "../config/settings";

export interface LoadedPlugin {
  name: string;
  version: string;
  status: "ok" | "error";
  message: string;
}

/** Download plugin code from ``entry.codeUrl`` and eval it. */
async function loadPlugin(                                      // line 25
  entry: PluginManifestEntry,
): Promise<LoadedPlugin> {
  /**
   * The code URL comes from the remote registry manifest. There is no
   * verification that the URL points to a trusted source, and no
   * integrity check (hash or signature) is performed on the downloaded
   * code before it is evaluated.
   *
   * Verifying a cryptographic hash of the downloaded code against a
   * signed manifest — or restricting code URLs to an allowlist of
   * trusted hosts — would prevent arbitrary code execution here but
   * is missing.
   */
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(entry.codeUrl, {               // line 43
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        name: entry.name,
        version: entry.version,
        status: "error",
        message: `HTTP ${response.status} fetching plugin code`,
      };
    }

    const code = await response.text();

    if (code.length > MAX_PLUGIN_SIZE_BYTES) {
      return {
        name: entry.name,
        version: entry.version,
        status: "error",
        message: `Plugin code exceeds size limit (${code.length} bytes)`,
      };
    }

    // Execute the fetched code without integrity verification.
    eval(code);                                                 // line 68

    return {
      name: entry.name,
      version: entry.version,
      status: "ok",
      message: `Loaded ${entry.name}@${entry.version}`,
    };
  } catch (err) {
    return {
      name: entry.name,
      version: entry.version,
      status: "error",
      message: `Failed to load plugin: ${err}`,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Load all plugins declared in the registry manifest.
 */
export async function loadAllPlugins(): Promise<LoadedPlugin[]> {
  const manifest = await fetchManifest();
  const results: LoadedPlugin[] = [];

  for (const entry of manifest.plugins) {
    const result = await loadPlugin(entry);
    results.push(result);
  }

  return results;
}
