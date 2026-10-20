# Manifest v4

The SDK validates and signs `specVersion: 4` manifests for Futurity custom-plugin
registration. Marketplace v3 manifests are a separate consumer contract; this SDK
no longer produces them. `PluginManifestSchema` validates complete wire manifests
and rejects versions 1, 2, and 3. Author options omit `specVersion`; the SDK always
sets its supported version before validation and signing.

## Migration

- Remove `specVersion` from your `pluginManifest` options; the SDK supplies it.
- Replace legacy `authForwarding: { ... }` with `auth: { type: "forwarding", ... }`.
- Use `PluginManifestSchema` instead of the removed `PluginManifestSchemaV1` or
  `PluginManifestSchemaCompat` exports.
- Custom registration supports `forwarding` and `none`, not `chained`.
  [Chained runtime utilities](chained-auth.md) remain available for separate host
  integrations; there is no automatic chained-to-custom migration.
- Keep signing keys. The endpoint remains `/.well-known/futurity/plugin` with
  `X-Futurity-Signature` (detached Ed25519 JWS).
- MCP, icon, and absolute authentication URLs must be HTTP(S). Icons are URLs,
  not emoji or data URLs.

This is a breaking library API change. Package versions and publishing are managed
separately; the manifest's own `version` remains the plugin's three-part version.

## Public plugins and governance

```typescript
import type { PluginManifestOptions } from "@futurity/plugins";

const manifest: PluginManifestOptions = {
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
`clock` (`wall` or `instant`), and `unit`. The top-level `icon` is an optional HTTP(S) URL.
These declarations are preserved in the signed payload; enforcement belongs to
the consuming platform, not this library.

## Signed registration metadata

`description`, `category`, and `metadata` are optional and nullable. Metadata supports:

- `tagline`, `overview`: strings.
- `oauth`: optional `token_body` (`form` or `json`), `setup_steps` (strings), and
  `console_url` (HTTP(S)).
- `features`: objects with `title`, `description`, `category` (`read`, `write`,
  `read_write`), and optional string `icon`.
- `permissions`: strings or objects with `scope`, `label`, `description`, `access`
  (`read`, `write`, `read_write`, `admin`), and required nullable HTTP(S) `docsUrl`.
- `setupType`: `user`, `admin`, or `none`.
- `links`: optional HTTP(S) `docs` and `privacy`.

These fields are included in the signed response, not supplied separately during
registration. Unknown object properties are stripped by schema parsing.

## Authentication and credential fields

Forwarding supports `authorization_code` (default), `client_credentials`, and
`urn:ietf:params:oauth:grant-type:saml2-bearer`. Authorization-code grants require
an HTTP(S) `authorizationEndpoint` and absolute HTTP(S) `tokenEndpoint`.
Organization grants may use a root-relative token path such as `/oauth/token`,
resolved by the platform against the configured `api_base_url`. Protocol-relative
paths, backslashes, whitespace, and fragments are rejected. Forwarding also accepts
optional nullable `extra_params`, a string-to-string map of authorization parameters.

`auth: { type: "none" }` means no OAuth exchange. Its optional `grantType` is
`none`, `api_key`, or `credentials`. Only explicit organization grants collect
credentials; per-user credentials without OAuth are unsupported.

Both auth modes accept optional nullable `credentials_schema`, an array of fields:
`key`, `label`, `type` (`input`, `password`, `textarea`, `x509-keypair`), and optional
`required`, `placeholder`, `help`, `secondaryKey`. Use `input` for text fields; aliases are not accepted.
Absent `required` means required to the platform; `false` is preserved.

- Keys must be nonempty and unique across primary and secondary keys.
- Only `x509-keypair` accepts `secondaryKey`, and it requires a nonempty one.
- `pattern` is rejected, not silently removed.
- A `none` grant cannot collect fields; `credentials` requires a nonempty array.
- Explicit field arrays for `api_key` must collect `api_key`; `client_credentials`
  must collect `api_base_url`, `client_id`, `client_secret`; SAML must collect
  `api_base_url`, `client_id`, `saml_subject_name_id`, `private_key_pem`, and
  `public_cert_pem` (which may be the keypair's secondary key).

Null or omitted field schemas remain null or omitted in the signed payload. The
platform supplies grant defaults; the SDK does not insert credential fields or
change credential delivery, token exchange, or request authentication runtime.
