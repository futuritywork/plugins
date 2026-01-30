# @futurity/plugins

A minimal MCP (Model Context Protocol) server library for Bun with auth forwarding support.

## Installation

```bash
bun add @futurity/plugins
```

## Quick Start

```typescript
import { z } from "zod";
import { mcp } from "@futurity/plugins";

const app = mcp({
  name: "my-server",
  version: "1.0.0",
});

app.tool("greet", {
  description: "Greet a user",
  input: z.object({
    name: z.string(),
  }),
  handler: async ({ name }) => {
    return { message: `Hello, ${name}!` };
  },
});

app.listen(3000);
```

```bash
bun run server.ts
# MCP server listening on http://localhost:3000/mcp
```

## API

### `mcp(options)`

Create an MCP application.

```typescript
const app = mcp({
  name: "my-server",           // required
  version: "1.0.0",            // required
  path: "/mcp",                // default: "/mcp"
  instructions: "...",         // optional system instructions
  capabilities: { ... },       // optional MCP capabilities
  pluginManifest: { ... },     // optional auth forwarding manifest
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

### `app.listen(port, transport?)`

Start the server.

```typescript
// HTTP (default)
await app.listen(3000);

// WebSocket
await app.listen(3000, "websocket");
```

## CORS

```typescript
import { mcp, cors } from "@futurity/plugins";

const app = mcp({ name: "server", version: "1.0.0" });

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
  oauth: {
    issuer: "https://auth.example.com",
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    tokenEndpoint: "https://auth.example.com/oauth/token",
    jwksUri: "https://auth.example.com/.well-known/jwks.json",
    scopesSupported: ["openid", "profile"],
  },
});
```

## Auth Forwarding

Auth forwarding lets the Futurity platform manage OAuth tokens on behalf of your plugin. Instead of implementing OAuth end-to-end, you declare your auth requirements in a signed manifest.

### 1. Generate a signing keypair

```bash
bun run keygen
```

This prints an Ed25519 keypair. Keep the private key secret; register the public key with the Futurity API.

### 2. Configure the plugin manifest

```typescript
const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  pluginManifest: {
    specVersion: 1,
    pluginId: "my-plugin",
    name: "My Plugin",
    version: "1.0.0",
    signingKey: process.env.FUTURITY_SIGNING_KEY!,
    authForwarding: {
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

### 3. Serve the manifest

The signed manifest is automatically served at:

```
GET /.well-known/futurity/plugin
```

The response includes an `X-Futurity-Signature` header with an Ed25519 JWS signature.

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
const app = mcp({ name: "server", version: "1.0.0" });

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

Run examples from the `examples/` directory:

```bash
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
  McpApp,
  McpAppOptions,
  ToolOptions,
  ResourceOptions,
  Middleware,
  AuthMiddleware,
  WellKnownEntry,
  PluginManifest,
  PluginManifestOptions,
  AuthForwarding,
  StreamableHttpServer,
  StreamableHttpServerOptions,
  StreamableHttpTransport,
  WebSocketTransport,
  WebSocketTransportOptions,
} from "@futurity/plugins";
```

## License

MIT
