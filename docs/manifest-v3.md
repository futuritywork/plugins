# Manifest v3

The library validates and signs manifests with `specVersion: 3`, matching Futurity
and Futurity Marketplace. Authentication modes (`forwarding`, `chained`, `none`)
are separate from the manifest version.

Every `mcp(options)` / `new McpApp(options)` requires `pluginManifest` and
`catalog`. Construction validates and signs the manifest immediately; generate an
Ed25519 keypair first and set `FUTURITY_SIGNING_KEY` to its private PKCS8 DER base64
key. Missing or invalid keys fail startup; production keys are never generated
automatically. See [Quick Start](../README.md#basic-usage).

The same parsed snapshot drives the signed endpoint and catalog identity:
`pluginId` → `slug`, `name` → `name`, `mcpUrl` → `mcp_url`. Catalog identity fields
are optional for JSON compatibility and are always overridden by the manifest.
Keep `catalog.grant_type` and other metadata explicit; auth is not inferred.
Later input mutations cannot change either response. MCP `name` and `version`
remain separate required options.

## Migration

- Supply `pluginManifest` with a valid signing key for every app, even public plugins.
- Supply `catalog: { grant_type: "none" }` for a public plugin (use your explicit
  grant for authenticated plugins); remove duplicated catalog identity if desired.
- Change `specVersion` from 1 or 2 to 3.
- Replace legacy `authForwarding: { ... }` with `auth: { type: "forwarding", ... }`.
- Replace imports of `PluginManifestSchemaV1` or `PluginManifestSchemaCompat` with
  `PluginManifestSchema`. Legacy versions are rejected, not automatically converted.
- Keep existing forwarding/chained configuration and signing keys. The signed
  endpoint remains `/.well-known/futurity/plugin` with `X-Futurity-Signature`.

This is a breaking library API change. Package versions and publishing are managed
separately; the manifest's own `version` remains the plugin's three-part version.

## Public plugins and governance

```typescript
import type { PluginManifestOptions } from "@futurity/plugins";

const manifest: PluginManifestOptions = {
  specVersion: 3,
  pluginId: "public-catalog",
  name: "Public Catalog",
  version: "1.0.0",
  mcpUrl: "https://catalog.example.com/mcp",
  signingKey: process.env.FUTURITY_SIGNING_KEY!,
  auth: { type: "none" },
  governance: {
    credential: "organization",
    purpose: "Public product catalog",
    defaultAccess: "open",
    datasets: {
      products: {
        title: "Products",
        fields: [{ name: "id", type: "string" }],
      },
    },
  },
};
```

Governance is optional. When present, `credential` (`organization` or `user`) and
`datasets` are required. Each dataset needs a title and at least one named, typed
field; dataset IDs cannot be empty or contain dots or whitespace. Field
`references: { dataset, field }` must resolve within the manifest, and every
`restrictedByDefault` entry must name a declared dataset.

Optional governance metadata includes `timezone`, `purpose`, `defaultAccess`,
`restrictedByDefault`, dataset `description`, `group`, `paths`, and
`probe: { tool, args }`. Fields can declare `identifier`, `references`, `nullable`,
`clock` (`wall` or `instant`), and `unit`. The top-level `icon` is an optional string.
These declarations are preserved in the signed payload; enforcement belongs to
the consuming platform, not this library.
