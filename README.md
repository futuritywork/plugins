# @futurity/plugins

A minimal MCP (Model Context Protocol) server library for Bun with auth forwarding support.

## Quick Start

### Create a new plugin

```bash
bunx create-futurity-plugin@latest my-plugin
cd my-plugin
cp .env.example .env
bun run keygen
bun run dev
```

### Or add to an existing project

```bash
bun add @futurity/plugins
```

### Basic usage

Every app requires a signed manifest, including public/no-auth plugins. Generate
an Ed25519 keypair once (`bun run keygen` in a scaffolded project, or the exported
`generateKeyPair()` utility), then set `FUTURITY_SIGNING_KEY` to the private PKCS8
DER base64 key. Keep it secret and stable; register only the public key. Startup
fails for a missing or invalid manifest/key. Keys are never generated automatically.

```ts
import { mcp, t, type PluginManifestOptions } from "@futurity/plugins";

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) throw new Error("FUTURITY_SIGNING_KEY is required; generate a keypair first");

const pluginManifest = {
  specVersion: 3,
  pluginId: "my-plugin",
  name: "My Plugin",
  version: "1.0.0",
  mcpUrl: "http://localhost:3000/mcp", // Use your public URL when deployed.
  auth: { type: "none" },
  signingKey,
} satisfies PluginManifestOptions;

const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  pluginManifest,
  catalog: { grant_type: "none" },
});

app.tool("hello", {
  description: "Say hello",
  input: t.obj({ name: t.str }),
  handler: async ({ name }) => ({
    greeting: `Hello, ${name}!`,
  }),
});

// Option A: Use the fetch handler (works in any runtime)
Bun.serve({ port: 3000, fetch: app.fetch });

// Option B: Convenience method (Bun only)
await app.listen(3000);
```

> **Note:** The WebSocket transport (`app.listen(port, "websocket")`) is Bun-only. The HTTP transport (`app.fetch`) works in any runtime that supports the Fetch API.

The snippets below reuse `pluginManifest` from Basic usage unless they declare
one inline. Set its identity, public MCP URL, and auth declaration for your plugin;
MCP `name` and `version` remain separate, required options.

## API

### `mcp(options)`

Create an MCP application. Options, including `pluginManifest` and `catalog`, are required for both
`mcp(options)` and `new McpApp(options)`.

```typescript
const app = mcp({
  name: "my-server",           // required
  version: "1.0.0",            // required
  path: "/mcp",                // default: "/mcp"
  instructions: "...",         // optional system instructions
  capabilities: { ... },       // optional MCP capabilities
  pluginManifest: { ... },     // required v3 manifest with signingKey
  catalog: { grant_type: "none" }, // required public marketplace metadata
});
```

### `app.tool(name, options)`

Register a tool.

```typescript
app.tool("add", {
  description: "Add two numbers",
  input: z.object({
    a: z.number(),
    b: z.number(),
  }),
  handler: async ({ a, b }) => {
    return { sum: a + b };
  },
});
```

Tools without input:

```typescript
app.tool("ping", {
  description: "Health check",
  handler: async () => {
    return { status: "ok" };
  },
});
```

### `app.resource(uri, options)`

Register a resource.

```typescript
app.resource("config://settings", {
  description: "Application settings",
  fetch: async () => {
    return { theme: "dark", language: "en" };
  },
});
```

### `app.use(plugin)`

Apply a plugin.

```typescript
import { cors } from "@futurity/plugins";

app.use(
  cors({
    allowOrigin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
  })
);
```

### `app.middleware(fn)`

Add middleware directly.

```typescript
app.middleware(async (req, next) => {
  console.log(`${req.method} ${req.url}`);
  return next(req);
});
```

### `app.fetch`

The standard Fetch API handler. Works in any runtime (Bun, Deno, Cloudflare Workers, Node with a fetch-compatible adapter, etc.):

```typescript
Bun.serve({ port: 3000, fetch: app.fetch });
```

### `app.listen(port, transport?)` (Bun only)

Convenience method to start the server. Requires Bun.

```typescript
// HTTP (default)
await app.listen(3000);

// WebSocket (Bun only)
await app.listen(3000, "websocket");
```

## CORS

```typescript
import { mcp, cors } from "@futurity/plugins";

const app = mcp({
  name: "server", version: "1.0.0",
  pluginManifest,
  catalog: { grant_type: "none" },
});

app.use(
  cors({
    allowOrigin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "Accept", "Mcp-Session-Id"],
    exposeHeaders: ["Mcp-Session-Id"],
    maxAge: 86400,
    credentials: false,
  })
);

app.listen(3000);
```

## OAuth

Configure OAuth metadata for `/.well-known/oauth-authorization-server`:

```typescript
const app = mcp({
  name: "server",
  version: "1.0.0",
  pluginManifest: {
    ...pluginManifest,
    auth: {
      type: "forwarding",
      grantType: "authorization_code",
      authorizationEndpoint: "https://auth.example.com/oauth/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      requiredScopes: ["openid", "profile"],
      deliveryMethod: "header",
    },
  },
  catalog: { grant_type: "authorization_code" },
  oauth: {
    issuer: "https://auth.example.com",
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    tokenEndpoint: "https://auth.example.com/oauth/token",
    jwksUri: "https://auth.example.com/.well-known/jwks.json",
    scopesSupported: ["openid", "profile"],
  },
});
```

## Public catalog

Every app requires a single marketplace-style listing, served at `GET /api/catalog`:

```typescript
import { mcp, type CatalogOptions } from "@futurity/plugins";

const catalog = {
  grant_type: "none",
  plugin_base_url: "https://plugin.example.com",
  description: "Search public records",
  metadata: {
    tagline: "Public record search",
    setupType: "none",
    links: { docs: "https://plugin.example.com/docs" },
  },
} satisfies CatalogOptions;

const app = mcp({ name: "my-plugin", version: "1.0.0", pluginManifest, catalog });
await app.listen(3000);
```

Or import a marketplace-shaped JSON config directly; no loader is required:

```typescript
import { mcp } from "@futurity/plugins";
import catalog from "./config/my-plugin.json";

const app = mcp({ name: "my-plugin", version: "1.0.0", pluginManifest, catalog });
Bun.serve({ port: 3000, fetch: app.fetch });
```

The response is a single JSON object, not Marketplace's array format. Consumers must
accept this object shape. `catalog` and its `grant_type` are required.
`slug`, `name`, and `mcp_url` are derived from the validated manifest's `pluginId`,
`name`, and `mcpUrl`. They are optional catalog inputs for compatibility with
marketplace-shaped JSON; **manifest values always override supplied values**,
including stale identities. Other fields remain explicit: neither `grant_type`
nor OAuth URLs, scopes, or keys are inferred from manifest auth.

`CatalogOptionsSchema` is exported for standalone metadata validation; it accepts
omitted identity fields. `mcp(options)` and `new McpApp(options)` validate the
manifest and catalog immediately and throw a Zod error for malformed metadata.
Signing also happens at construction, so missing or invalid private keys fail
before the app serves requests. Imported JSON strings are validated at runtime,
including metadata and credential field enums.

Optional top-level fields default to `null`, except `is_official` and `popular`
(`false`). These include `description`, `category`, `icon_url`, `auth_url`,
`token_url`, `scopes`, `extra_params`, `plugin_base_url`, `credential_schema` and
`metadata`. Nested optional metadata/credential fields remain omitted. `auth_type`
is derived like the marketplace: `none` → `free`, `api_key` → `api_key`, a supplied
credential schema (even an empty array) → `admin`, otherwise `oauth`.
`marketplace_sign_in` defaults to `null`; set an explicit boolean only when known.
`signing_public_key` defaults to `null`; supply the SPKI DER base64 **public** key
explicitly when publishing a signed manifest. No keys are derived from the manifest,
and catalog configuration does not implement an OAuth broker or change MCP auth.

**Public-only data:** this route bypasses MCP `auth`, but runs after application
middleware, which can wrap or block it. Unknown fields (including `client_id`,
`client_secret`, and private-key fields) are stripped from fixed-shape objects,
including nested metadata and credential definitions. Every recognized value is
public: never put secrets in descriptions, URLs, credential hints, or the
open-ended `extra_params` map. Prefer a dedicated public config file.

The route works with `app.fetch` and both HTTP and WebSocket `app.listen` modes.
It accepts only GET; other methods receive `405` with `Allow: GET` unless middleware
handles them first (for example, CORS preflight). The listing is snapshotted at
construction from the same parsed manifest used for the signed endpoint; later
catalog or manifest mutations do not change either response or their shared identity.

## Authentication

All signed plugin manifests use `specVersion: 3`. See [Manifest v3](docs/manifest-v3.md)
for migration, public (`none`) auth, and governance metadata.

There are two authenticated modes for Futurity plugins:

| Mode | Description | Use Case |
|------|-------------|----------|
| **Auth Forwarding** (v1) | Platform manages OAuth tokens | Simple integrations |
| **Chained Auth** (v2) | Plugin manages sessions & tokens | Complex integrations, multi-service |

### Auth Forwarding (v1)

Auth forwarding lets the Futurity platform manage OAuth tokens on behalf of your plugin. Instead of implementing OAuth end-to-end, you declare your auth requirements in a signed manifest.

#### 1. Generate a signing keypair

```bash
bun run keygen
```

This prints an Ed25519 keypair. Keep the private key secret; register the public key with the Futurity API.

#### 2. Configure the plugin manifest

```typescript
const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  catalog: { grant_type: "authorization_code" },
  pluginManifest: {
    specVersion: 3,
    pluginId: "my-plugin",
    name: "My Plugin",
    version: "1.0.0",
    signingKey: process.env.FUTURITY_SIGNING_KEY!,
    auth: {
      type: "forwarding",
      grantType: "authorization_code",
      tokenEndpoint: "https://auth.example.com/oauth2/token",
      authorizationEndpoint: "https://auth.example.com/oauth2/authorize",
      requiredScopes: ["read", "write"],
      deliveryMethod: "header",  // "header" (default) or "query"
      maxTokenTtl: 3600,         // optional, seconds
    },
    mcpUrl: "https://my-plugin.example.com/mcp",
  },
});
```

#### 3. Serve the manifest

The signed manifest is automatically served at:

```
GET /.well-known/futurity/plugin
```

The response includes an `X-Futurity-Signature` header with an Ed25519 JWS signature.

### Chained Auth (v2)

For plugins that need to manage their own sessions and store third-party tokens, use chained auth. The plugin controls the OAuth flow and issues its own tokens.

```typescript
const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  catalog: { grant_type: "authorization_code" },
  pluginManifest: {
    specVersion: 3,
    pluginId: "my-plugin",
    name: "My Plugin",
    version: "1.0.0",
    signingKey: process.env.FUTURITY_SIGNING_KEY!,
    auth: {
      type: "chained",
      authorizationEndpoint: "https://plugin.example.com/auth/authorize",
      callbackEndpoint: "https://plugin.example.com/auth/callback",
      tokenEndpoint: "https://plugin.example.com/auth/token",
      requiredUserContext: ["user_id", "email"],
    },
    mcpUrl: "https://plugin.example.com/mcp",
  },
  chainedAuth: {
    sessionStore: mySessionStore,
    platformJwksUrl: "https://platform.example.com/.well-known/jwks.json",
    pluginSigningKey: process.env.PLUGIN_SIGNING_KEY!,
    handlers: {
      onAuthorize: async (userContext, platformState, platformCallback) => { ... },
      onCallback: async (req) => { ... },
      onToken: async (req) => { ... },
    },
  },
});
```

See [docs/chained-auth.md](docs/chained-auth.md) for full documentation including:
- Complete implementation guide
- Request binding for anti-replay protection
- Session management
- Platform integration guide

### Signing utilities

```typescript
import { generateKeyPair, signPayload, verifyPayload } from "@futurity/plugins";

const { privateKey, publicKey } = generateKeyPair();
const jws = signPayload('{"hello":"world"}', privateKey);
const valid = verifyPayload('{"hello":"world"}', jws, publicKey); // true
```

## Authentication

Custom auth middleware:

```typescript
const app = mcp({
  name: "server",
  version: "1.0.0",
  pluginManifest,
  catalog: { grant_type: "api_key" },
  auth: async (req) => {
    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    if (!token) return false;
    return await validateToken(token);
  },
});
```

## Stateful Patterns

```typescript
const state = {
  counter: 0,
  items: new Map<string, string>(),
};

app.tool("increment", {
  handler: async () => {
    state.counter++;
    return { counter: state.counter };
  },
});

app.tool("set", {
  input: z.object({ key: z.string(), value: z.string() }),
  handler: async ({ key, value }) => {
    state.items.set(key, value);
    return { key, value };
  },
});
```

## Multi-Session Support

The HTTP transport supports multiple concurrent client sessions.

```typescript
const app = mcp({
  name: "server", version: "1.0.0",
  pluginManifest,
  catalog: { grant_type: "none" },
});

app.tool("example", { handler: async () => ({ ok: true }) });

await app.listen(3000);

console.log(app.activeSessions);
await app.stop();
```

## Direct Transport Usage

```typescript
import { StreamableHttpServer, StreamableHttpTransport } from "@futurity/plugins";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new StreamableHttpServer({
  port: 3000,
  path: "/mcp",
  onSession: async (transport: StreamableHttpTransport) => {
    const mcp = new McpServer({ name: "server", version: "1.0.0" });
    await mcp.connect(transport);
  },
});

await server.start();
```

## Examples

The `examples/` directory contains runnable examples. First generate a keypair
using the signing utility above and export its private half as
`FUTURITY_SIGNING_KEY`; every example requires it. Use public URLs when deployed.
Clone the repo and run the examples directly:

```bash
git clone https://github.com/futuritywork/plugins.git
cd plugins
bun examples/calculator.ts      # Math operations and unit conversion
bun examples/cors.ts            # CORS configuration
bun examples/database.ts        # Document database
bun examples/filesystem.ts      # Virtual filesystem
bun examples/oauth.ts           # OAuth metadata
bun examples/stateful.ts        # Counter, notes, key-value store
bun examples/todo-app.ts        # Todo list with CRUD
bun examples/weather-api.ts     # Weather data API
bun examples/monday/index.ts    # monday.com integration with auth forwarding
```

## monday.com Integration Example

A complete monday.com MCP server is included demonstrating auth forwarding:

```bash
# Set environment variables
export FUTURITY_SIGNING_KEY="your-private-key-base64"

# Run the server
bun examples/monday/index.ts
```

Features:
- **Boards**: List and get board details
- **Items**: Full CRUD operations
- **Updates**: Read and create comments
- **Groups**: Create new groups

## Types

```typescript
import type {
  // App
  McpApp,
  McpAppOptions,
  ToolOptions,
  ResourceOptions,
  Middleware,
  AuthMiddleware,
  WellKnownEntry,
  CatalogOptions,

  // Plugin Manifest
  PluginManifest,
  PluginManifestOptions,
  Auth,
  AuthForwarding,
  ChainedAuth,

  // Chained Auth
  Session,
  PendingSession,
  SessionStore,
  UserContext,
  ChainedAuthConfig,
  ChainedAuthHandlers,
  PlatformAssertionClaims,
  VerifiedPlatformAssertion,

  // Transports
  StreamableHttpServer,
  StreamableHttpServerOptions,
  StreamableHttpTransport,
  WebSocketTransport,
  WebSocketTransportOptions,
} from "@futurity/plugins";
```

### Chained Auth Utilities

```typescript
import {
  // Session management
  createPendingSession,
  activateSession,
  expireSession,
  revokeSession,
  isSessionValid,
  InMemorySessionStore,

  // Token generation
  generatePluginToken,
  validatePluginToken,
  generateRefreshToken,

  // State management
  generateChainedState,
  parseChainedState,

  // Request binding
  hashPluginToken,
  hashRequest,
  validatePlatformAssertion,
  validateAuthenticatedRequest,

  // JWT validation
  validateUserContextJwt,
  clearJwksCache,
} from "@futurity/plugins";
```

## License

Copyright © 2025 Futurity Technologies Pte Ltd

This software is licensed under the Business Source License 1.1 (BSL). You may use, copy, modify, and redistribute for non-production purposes. Production use requires a commercial license until the Change Date (2030-01-01), after which the software becomes available under the GNU General Public License v3.0 or later.

See [LICENSE](LICENSE) for full terms.
