# @futurity/plugins

A minimal MCP (Model Context Protocol) server library for Bun with auth forwarding support.

## Quick Start

### Create a new plugin

```bash
bunx create-futurity-plugin@latest my-plugin
cd my-plugin
cp .env.example .env
bun run keygen # copy the private key into FUTURITY_SIGNING_KEY in .env
bun run dev
```

### Or add to an existing project

```bash
bun add @futurity/plugins
```

### Basic usage

```ts
import { mcp, t } from "@futurity/plugins";

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) throw new Error("Set FUTURITY_SIGNING_KEY to your Ed25519 private key.");

const pluginManifest = {
  pluginId: "my-plugin",
  name: "My Plugin",
  version: "1.0.0",
  mcpUrl: `${process.env.PUBLIC_URL ?? "http://localhost:3000"}/mcp`,
  auth: { type: "none" as const },
  signingKey,
};

const app = mcp({
  pluginManifest,
  name: "my-plugin",
  version: "1.0.0",
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

## API

### `mcp(options)`

Create an MCP application. `pluginManifest` is required, including for WebSocket
servers; omitting it throws at construction. The manifest is validated and signed
when `app.fetch` is first accessed or a transport starts. The SDK supplies
`specVersion` automatically; you maintain only your plugin's release `version`.

The snippets below reuse `pluginManifest` from Basic usage; configure its identity,
auth, and public MCP URL for your own plugin.

```typescript
const app = mcp({
  name: "my-server",           // required
  version: "1.0.0",            // required
  path: "/mcp",                // default: "/mcp"
  instructions: "...",         // optional system instructions
  capabilities: { ... },       // optional MCP capabilities
  pluginManifest,             // required signed v4 manifest
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

const app = mcp({ name: "server", version: "1.0.0", pluginManifest });

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
  pluginManifest,
  oauth: {
    issuer: "https://auth.example.com",
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    tokenEndpoint: "https://auth.example.com/oauth/token",
    jwksUri: "https://auth.example.com/.well-known/jwks.json",
    scopesSupported: ["openid", "profile"],
  },
});
```

## Authentication

Custom-plugin manifests use `specVersion: 4` only. See [Manifest v4](docs/manifest-v4.md)
for migration, signed metadata, organization credentials, and governance.

Custom registration supports `forwarding` (platform-managed OAuth) and `none`
(no OAuth exchange, optionally with explicit organization credentials).
Chained authentication is not supported by custom registration.

### Auth Forwarding (v1)

Auth forwarding lets the Futurity platform manage OAuth tokens on behalf of your plugin. Instead of implementing OAuth end-to-end, you declare your auth requirements in a signed manifest.

#### 1. Generate a signing keypair

```bash
bun run keygen
```

In a generated project, this prints an Ed25519 keypair. Set `FUTURITY_SIGNING_KEY`
to the private key before starting the server. Keep the private key secret; register the public key with the Futurity API.

#### 2. Configure the plugin manifest

```typescript
const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  pluginManifest: {
    pluginId: "my-plugin",
    name: "My Plugin",
    version: "1.0.0",
    signingKey, // required key loaded above
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

### Standalone chained-auth runtime

The session, token, and `chainedAuth` routing utilities remain available for
separately integrated hosts. They are not a v4 manifest authentication option;
`PluginManifestSchema` rejects `auth.type: "chained"`. Do not declare `none` as a
workaround for a chained plugin.

See [docs/chained-auth.md](docs/chained-auth.md) for the runtime protocol and
host integration requirements.

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
const app = mcp({ name: "server", version: "1.0.0", pluginManifest });

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

The `examples/` directory in this repo contains runnable examples. Clone the repo and run them directly:

```bash
git clone https://github.com/futuritywork/plugins.git
cd plugins
# Generate a keypair; keep the private key secret.
bun -e 'import { generateKeyPair } from "./packages/plugins/src/signing"; console.log(generateKeyPair());'
export FUTURITY_SIGNING_KEY="<privateKey from the output>"
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

Each example requires `FUTURITY_SIGNING_KEY`. The local examples publish
`http://localhost:3000/mcp` by default; set `PUBLIC_URL` to the public HTTPS base
URL before registration. They use `auth.type: "none"` because their tools do not
require OAuth; `oauth.ts` demonstrates discovery metadata only.

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
