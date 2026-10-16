import type { PluginManifestOptions } from "../pluginManifest";
import { generateKeyPair } from "../signing";

// Ephemeral keys shared by app-level tests; no private key is checked in.
export const manifestKeys = generateKeyPair();
export const pluginManifest: PluginManifestOptions = {
  specVersion: 3,
  pluginId: "test-plugin",
  name: "Test Plugin",
  version: "1.0.0",
  mcpUrl: "https://plugin.example.com/mcp",
  auth: { type: "none" },
  signingKey: manifestKeys.privateKey,
};
