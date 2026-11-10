# @futurity/plugins

A minimal MCP (Model Context Protocol) server library for Bun that serves a
Futurity plugin manifest and verifies the Futurity identity token on every call.

This repo also holds `@futurity/plugin-manifest`, the one validator for the
manifest contract (spec 5). The SDK, the Futurity platform and the marketplace
all parse manifests with it. See [Manifest v5](docs/manifest-v5.md).

## Quick Start

### Create a new plugin

```bash
bunx create-futurity-plugin@latest my-plugin
cd my-plugin
cp .env.example .env
bun run dev
```

### Or add to an existing project

```bash
bun add @futurity/plugins
```

### Basic usage

```ts
import { FUTURITY_META_KEY, mcp, t, type PluginManifestInput } from "@futurity/plugins";

const manifest: PluginManifestInput = {
  name: "com.example/my-plugin",
  title: "My Plugin",
  description: "What this plugin connects Futurity to",
  version: "1.0.0",
  remotes: [{ type: "streamable-http", url: "https://my-plugin.example.com/mcp" }],
  _meta: {
    [FUTURITY_META_KEY]: {
      specVersion: 5,
      developer: { email: "developer@example.com" },
      credentials: [
        {
          id: "api-key",
          label: "Organization API key",
          holder: "org",
          method: { type: "secrets" },
          fields: [
            { key: "api_key", label: "API key", kind: "plugin_secret", scope: "install", input: "password", header: "X-Api-Key" },
          ],
        },
      ],
    },
  },
};

const app = mcp({
  manifest,
  instructions: "Use for questions about My Plugin's data.",
  futurity: {
    issuers: [{ issuer: "https://api-v4.futurity.work", jwksUrl: "https://api-v4.futurity.work/oauth/jwks" }],
  },
});

app.tool("hello", {
  description: "Say hello",
  input: t.obj({ name: t.str }),
  output: t.obj({ greeting: t.str }),
  annotations: { readOnlyHint: true },
  handler: async ({ name }, { org, user }) => ({
    greeting: `Hello, ${name}! (org ${org.id}, user ${user.id})`,
  }),
});

// Serve with the fetch handler (works in any runtime)
Bun.serve({ port: 3000, fetch: app.fetch });
```

On Bun you can replace the `Bun.serve` line with `await app.listen(3000);`.
Use one or the other: both bind the port.

> **Note:** The WebSocket transport (`app.listen(port, "websocket")`) is Bun-only
> and carries no caller identity, so it only runs on apps built with
> `futurity: false`. The HTTP transport (`app.fetch`) works in any runtime that
> supports the Fetch API.

## API

### `mcp(options)`

```typescript
const app = mcp({
  manifest,                    // required spec 5 manifest
  futurity: { issuers: [{ issuer, jwksUrl }] }, // required; or false to serve without identity
  instructions: "...",         // optional, sent in the initialize result
  capabilities: { ... },       // optional MCP capabilities
  path: "/mcp",                // default: "/mcp"
  middleware: [ ... ],         // optional
});
```

The manifest is validated with `@futurity/plugin-manifest` when the app is
built; a broken rule throws with every error and its path. The SDK accepts
`http://localhost` URLs so a plugin can run locally; Futurity applies the
production rules (https only) when it fetches the manifest. The validated
manifest is served unsigned as JSON at `GET /.well-known/futurity/plugin`.

The MCP `serverInfo` comes from the manifest: `name`, `title`, `description`,
`version`, `icons` and `websiteUrl`.

### Futurity identity

With `futurity: { issuers }`, every request to the MCP path must carry
`Authorization: Bearer <jwt>`. Each entry in `issuers` is one Futurity
deployment the plugin trusts, with its own `issuer` and `jwksUrl`, so one plugin
deployment can serve production, staging and dev. The SDK picks the entry whose
`issuer` equals the token's `iss` (or a wildcard entry that covers it, see
[Futurity issuers](#futurity-issuers)), refuses a token from any other issuer,
verifies the signature against that entry's JWKS only (fetched with `jose` and
cached), and checks the claims (`sub`, `org_id`, `holder`, `credential_option`, `exp` at most five
minutes after `iat`, `jti`). A missing or invalid token gets a JSON 401:

```json
{ "error": "unauthorized", "error_description": "Missing Futurity identity token in Authorization" }
```

Futurity sets the token's `aud` to the manifest's remote URL exactly as
written, placeholders included (`https://{tenant}.example.com/mcp`, not the
resolved URL). The SDK accepts only that value. It never derives the audience
from the request, because the caller controls the Host header, so a token
minted for another plugin is refused.

The token's `credential_option` must name an option in the manifest, and its
`holder` must match that option. The SDK then reads the option's declared
headers into `credentials`, keyed by field key. A required field whose header is
missing gets a JSON 400 (`missing_credential`). For an OAuth option that
delivers its token in a header, the token is in `credentials.access_token`, and
each `tokenResponseFields` and `callbackQueryFields` value is under its `key`.
A setup field without a header is used only by Futurity and never appears in
`credentials`.

A session belongs to the issuer, org and user that opened it; requests from
another caller do not find it.

The SDK does not track `jti`, so it does not reject a replayed token inside its
five-minute lifetime. A plugin that needs replay protection keeps its own set of
seen `jti` values.

#### Futurity issuers

The token's `iss` is the origin of the Futurity API that called you:

| Deployment | `issuer` | `jwksUrl` |
| --- | --- | --- |
| Production | `https://api-v4.futurity.work` | `https://api-v4.futurity.work/oauth/jwks` |
| Staging | `https://api-v4-staging.futurity.work` | `https://api-v4-staging.futurity.work/oauth/jwks` |
| Local development | `http://localhost:4000` | `http://localhost:4000/oauth/jwks` |

A self-hosted Futurity deployment issues tokens from its own `API_URL` origin.

Since 4.1.0, an `issuer` whose first host label is `*` trusts every origin below
that host. `{ issuer: "https://*.futurity.work", jwksUrl: "/oauth/jwks" }` trusts
production, staging and every developer tunnel such as
`https://a1b2c3d4.futurity.work`. The token's `iss` must be a bare origin with the
same scheme and port and at least one label before `.futurity.work`, so
`https://futurity.work.evil.com` and `http://x.futurity.work` are refused. A
wildcard entry's `jwksUrl` is a path, resolved against the token's `iss`. An exact
entry wins over a wildcard. The SDK keeps the key sets of at most 256 matched
origins and starts again past that.

#### Delivery headers

Every MCP request from Futurity carries:

- `Authorization: Bearer <identity token>`.
- One header per field that declares `header` (setup and `plugin_secret`
  fields). A `futurity_secret` field is never sent.
- For an OAuth option with `delivery: { header }`: the access token in that
  header, plus one header per `tokenResponseFields` and `callbackQueryFields`
  entry.

An option with `delivery: "mcp_authorization"` is for a vendor MCP server that
does not use the SDK: Futurity sends the vendor's OAuth token in
`Authorization` and no identity token. It takes any client: `dcr` when
the vendor registers clients dynamically, `futurity` or `install` when it does
not.

### `app.tool(name, options)`

```typescript
app.tool("delete_item", {
  description: "Delete an item",
  input: z.object({ id: z.string() }),
  output: z.object({ deleted: z.boolean() }),
  annotations: { destructiveHint: true, idempotentHint: true },
  handler: async ({ id }, { org, user, holder, credentials, signal }) => {
    await fetch(`https://api.example.com/items/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${credentials.api_key}` },
      signal,
    });
    return { deleted: true };
  },
});
```

`annotations` are the standard MCP tool annotations (`title`, `readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`) and are sent to clients
unchanged. Futurity groups tools by them alone: `readOnlyHint: true` is read,
`destructiveHint: true` is delete, anything else is write. Admins choose per
group or per tool whether calls run, ask first, or are blocked.

The handler's second argument is the call context:

| Field | With `futurity` | With `futurity: false` |
| --- | --- | --- |
| `issuer` | the trusted `iss` that signed the call | `null` |
| `org` | `{ id }` from `org_id` | `null` |
| `user` | `{ id }` from `sub` | `null` |
| `holder` | `"org"`, `"user"`, `"plugin"` or `"none"` | `null` |
| `credentials` | declared header values by field key | `{}` |
| `signal` | aborts on cancellation or disconnect | same |

`output` is required on every tool. It declares the **final handler result**,
not the upstream response, and is advertised as MCP `outputSchema`, so a tool
without it does not compile. A call returns its parsed result as
`structuredContent` and JSON text in `content`. Output parsing validates the
complete schema, including async refinements and strict-object rules, applies
defaults, and strips unknown fields unless the object schema preserves or
rejects them. Parsed results are also checked against the generated JSON Schema
with the MCP SDK's default AJV validator, on the JSON a client receives. A key
whose parsed value may be `undefined` (`z.unknown()`, `z.any()`, `.optional()`)
is not listed as required.

A result that fails either check never fails the call. The SDK returns the
result as the handler produced it, and reports the mismatch. A JSON object is
still sent as `structuredContent`; any other value (`null`, an array, a string)
is sent as text only. A client that enforces `outputSchema` itself, such as
the MCP SDK's `Client.callTool`, can still refuse that answer; Futurity does
not. Reports go to `console.warn` until you set a handler:

```ts
import { setOutputViolationHandler } from "@futurity/plugins";

setOutputViolationHandler((report) => {
  // { caller: tool name, schema, issues, timestamp }
});
```

`issues` lists each path that missed, with its message and code, in at most
2,000 characters. A report never carries a value from the result, since results
carry customer data. A handler that throws or rejects does not affect the call.

The schema must be an object or a union of objects, convertible to draft-7 JSON
Schema in output mode, with every pattern a valid unicode regular expression,
as AJV compiles it. A tool's AJV validator is compiled on its first call. A
union is advertised as `{ "type": "object", "anyOf": [...] }`. `app.tool()`
throws, naming the tool, on anything else: a root array, primitive or
`z.unknown()`, an unrepresentable field (such as `z.date()`), an invalid JSON
Schema pattern, a pipeline (including transforms and preprocessors), or an
`.overwrite()` check, even a nested one. Wrap arrays and primitives in an object.

`input` is any Zod schema whose JSON Schema is an object: a plain, strict or
loose object, an object with refinements, or a union of objects. Arguments are
parsed with the whole schema, so strict objects refuse unknown keys and
refinements run. `tools/list` advertises the same schema in draft-7 input mode;
a union is advertised as `{ "type": "object", "anyOf": [...] }`. A non-object
input (such as `z.string()`) throws when the tool is registered. Tools without an
input schema receive `{}` as their handler's first argument.

An optional `listedInput(schema, context)` sets the input schema that one
connection's `tools/list` advertises, for example to name that tenant's own
values. It receives the schema from `input` and the handler's context, and calls
are still parsed with `input`.

```typescript
app.tool("branch_sales", {
  input: z.object({ branch_id: z.number().int() }),
  output: z.object({ total: z.number() }),
  listedInput: async (schema, { credentials }) => {
    const branches = await listBranches(credentials.api_key);
    const oneOf = branches.map((b) => ({ const: b.id, title: b.name }));
    const branch_id = { type: "integer", oneOf };
    return { ...schema, properties: { ...schema.properties, branch_id } };
  },
  handler: async ({ branch_id }) => salesFor(branch_id),
});
```

The signal aborts when the MCP client cancels that request or the SDK connection
closes. Cancellation is cooperative: pass the signal to downstream I/O or check
`signal.throwIfAborted()` during work. It does not undo completed side effects.

### `app.resource(uri, options)`

```typescript
app.resource("config://settings", {
  description: "Application settings",
  fetch: async ({ org }) => ({ org: org.id, theme: "dark" }),
});
```

`fetch` receives the same context as a tool handler.

### `app.use(plugin)` and `app.middleware(fn)`

```typescript
app.middleware(async (req, next) => {
  console.log(`${req.method} ${req.url}`);
  return next(req);
});
```

### `app.fetch`

The standard Fetch API handler:

```typescript
Bun.serve({ port: 3000, fetch: app.fetch });
```

### `app.listen(port, transport?)` (Bun only)

```typescript
await app.listen(3000);              // HTTP (default)
await app.listen(3000, "websocket"); // only with futurity: false
```

## CORS

Futurity calls plugins from its servers, so most plugins need no CORS. For
browser clients, list the exact origins allowed to call:

```typescript
import { cors } from "@futurity/plugins";

app.use(
  cors({
    origins: ["https://app.futurity.work"],
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "Accept", "Mcp-Session-Id"],
    exposeHeaders: ["Mcp-Session-Id"],
    maxAge: 86400,
    credentials: false,
  })
);
```

A listed origin is echoed in `Access-Control-Allow-Origin`. An unlisted origin
gets no CORS headers, and with no origins listed nobody does. `"*"` is refused
when the policy is built.

## Multi-Session Support

The HTTP transport supports multiple concurrent client sessions.

```typescript
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

The `examples/` directory contains runnable examples. They run against the SDK
source through `tsconfig.examples.json`:

```bash
git clone https://github.com/futuritywork/plugins.git
cd plugins
bun install
bun --tsconfig-override=tsconfig.examples.json examples/calculator.ts
```

| Example | What it shows |
| --- | --- |
| `calculator.ts` | Math operations and unit conversions |
| `cors.ts` | A CORS origin list |
| `database.ts` | Document database |
| `filesystem.ts` | Virtual filesystem |
| `stateful.ts` | Counter, notes, key-value store |
| `todo-app.ts` | Todo list with CRUD and annotations |
| `weather-api.ts` | Weather data API |
| `monday/index.ts` | monday.com with per-person OAuth and identity verification |

The local examples use `futurity: false` and a manifest with one option held by
no one, so any MCP client can call them on `http://localhost:3000/mcp`. Set
`PORT` to listen elsewhere and `PUBLIC_URL` to change the remote they publish. The monday.com example reads
`BASE_URL` for its remote instead, and verifies the identity token: set
`FUTURITY_URL` to the one Futurity API origin it trusts (see
[Futurity issuers](#futurity-issuers)). `FUTURITY_ISSUERS` is a different
setting: the Futurity marketplace gateway reads it as a comma-separated list of
origins. A plugin built from this SDK or its scaffold reads `FUTURITY_URL`.

To add an example to Futurity, an administrator opens **Atlas**, presses
**Add**, picks **Integration or MCP server URL** and enters the base URL
(`http://localhost:3000`). The `/mcp` address the server prints works too:
Futurity also looks for the manifest one level up.

An OAuth option in a plugin your organization registers uses `client: "install"`
(the administrator enters the organization's `client_id` and `client_secret` at
install) or `client: "dcr"`. `client: "futurity"` uses an OAuth client that only
Futurity holds, so it works only for plugins in the Futurity marketplace, and
Futurity refuses it when an organization adds a plugin. The monday.com example
uses `client: "install"` with the two install fields (see
[Manifest v5](docs/manifest-v5.md)): the administrator enters the client ID and
secret of the organization's own monday.com app when adding it.

### Repository verification

```bash
bun install --frozen-lockfile
bun run check
bun run test
bun run build
```

`check` typechecks both packages, all examples, and the scaffold template
against the local source, without requiring a prior build.

## Types

```typescript
import type {
  // App
  McpApp,
  McpAppOptions,
  ToolOptions,
  ToolContext,
  ResourceOptions,
  Middleware,
  FuturityOptions,
  TrustedIssuer,
  FuturityIdentity,
  NoIdentity,

  // Manifest (re-exported from @futurity/plugin-manifest)
  PluginManifest,
  PluginManifestInput,
  FuturityExtension,
  CredentialOption,
  CredentialField,
  OAuthMethod,
  FuturityIdentityClaims,

  // Transports
  StreamableHttpServer,
  StreamableHttpServerOptions,
  StreamableHttpTransport,
  WebSocketTransport,
  WebSocketTransportOptions,
} from "@futurity/plugins";
```

## Releasing

Publish `@futurity/plugin-manifest` first, then `@futurity/plugins`, then
`create-futurity-plugin`. The SDK's type declarations import the manifest package,
and a scaffold installs the SDK at the version its template names.

## License

Copyright © 2025 Futurity Technologies Pte Ltd

This software is licensed under the Business Source License 1.1 (BSL). You may use, copy, modify, and redistribute for non-production purposes. Production use requires a commercial license until the Change Date (2030-01-01), after which the software becomes available under the GNU General Public License v3.0 or later.

See [LICENSE](LICENSE) for full terms.
