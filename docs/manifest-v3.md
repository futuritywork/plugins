# Manifest v3

The library validates and signs manifests with `specVersion: 3`, matching Futurity
and Futurity Marketplace. Authentication modes (`forwarding`, `chained`, `none`)
are separate from the manifest version.

## Migration

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
