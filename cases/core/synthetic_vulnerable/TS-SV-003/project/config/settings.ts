/**
 * Plugin agent configuration.
 */

export const REGISTRY_URL =
  process.env.PLUGIN_REGISTRY_URL ?? "https://plugins.example.com/v1";

export const FETCH_TIMEOUT_MS = 15_000;

export const MAX_PLUGIN_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

export const MAX_PLUGINS = 20;

/**
 * Trusted registry hosts. NOTE: This allowlist exists only in config —
 * the plugin loader never checks it before fetching or evaluating code.
 */
export const TRUSTED_REGISTRIES = [
  "plugins.example.com",
  "registry.internal.example.com",
];
