import { FUTURITY_META_KEY, type CredentialField, type CredentialOption, type PluginManifestInput } from "./schema";
import { parsePluginManifest } from "./parse";

export function field(overrides: Partial<CredentialField> = {}): CredentialField {
  return { key: "tenant", label: "Tenant", kind: "setup", scope: "install", input: "text", header: "X-Tenant", ...overrides };
}

export function option(overrides: Partial<CredentialOption> = {}): CredentialOption {
  return { id: "default", label: "Default", holder: "none", method: { type: "none" }, fields: [], ...overrides };
}

export function manifest(credentials: CredentialOption[] = [option()], overrides: Partial<PluginManifestInput> = {}): PluginManifestInput {
  return {
    name: "work.futurity/esb",
    title: "ESB",
    description: "Sales and inventory from ESB Core",
    version: "1.0.0",
    remotes: [{ type: "streamable-http", url: "https://esb.example.com/mcp" }],
    _meta: {
      [FUTURITY_META_KEY]: { specVersion: 5, developer: { email: "dev@example.com" }, credentials },
    },
    ...overrides,
  };
}

/** The readable errors for a manifest, empty when it is valid. */
export function problems(value: unknown, development = false): string[] {
  const result = parsePluginManifest(value, { development });
  return result.success ? [] : result.errors;
}
