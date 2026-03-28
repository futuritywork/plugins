# @futurity/plugins Package Refactor

## Goal

Refactor the plugins repo from a fork-and-build template into a publishable npm
package (`@futurity/plugins`) with a companion scaffolder
(`create-futurity-plugin`). This enables proper schema versioning and a cleaner
developer workflow: install the package, import what you need, build your plugin.

## Repo Structure

The repo becomes a Bun workspace monorepo:

```
plugins/
├── package.json                    # workspace root
├── packages/
│   ├── plugins/                    # @futurity/plugins
│   │   ├── src/
│   │   │   ├── index.ts            # barrel re-exports
│   │   │   ├── app.ts              # mcp() factory, McpApp
│   │   │   ├── types.ts
│   │   │   ├── signing.ts
│   │   │   ├── cors.ts
│   │   │   ├── oauth.ts
│   │   │   ├── chainedAuth.ts
│   │   │   ├── pluginManifest.ts
│   │   │   ├── toolkit.ts
│   │   │   └── transports/
│   │   │       ├── streamableHttp.ts
│   │   │       └── websocket.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── create-plugin/              # create-futurity-plugin
│       ├── index.ts                # CLI entry
│       ├── template/               # starter files
│       │   ├── src/index.ts
│       │   ├── package.json.tmpl
│       │   ├── tsconfig.json
│       │   └── .gitignore
│       └── package.json
├── examples/                       # reference only, not published
├── docs/
└── tsconfig.json
```

## Public API Surface

### Main entry

```ts
import { mcp, t, cors } from "@futurity/plugins";
```

Exports: `mcp`, `McpApp`, `t`, `cors`, all types (`PluginManifest`, `Session`,
`UserContext`, `DangerLevel`, `SessionStore`, `Middleware`, `AuthMiddleware`,
etc.), manifest schemas, chained auth utilities, signing utilities.

### Subpath exports

```ts
import { signPayload, verifyPayload, generateKeyPair } from "@futurity/plugins/signing";
import { cors } from "@futurity/plugins/cors";
import { oauthMetadataSchema } from "@futurity/plugins/oauth";
```

For consumers who want tree-shaking or to avoid pulling in the full library.

### Key API change: `app.fetch`

`app.fetch` becomes the primary interface. `app.listen()` stays as a Bun
convenience.

```ts
const app = mcp({ name: "my-plugin", version: "1.0.0" });

// Primary — bring your own server
Bun.serve({ port: 3000, fetch: app.fetch });

// Convenience — still works, Bun-only
await app.listen(3000);
```

### WebSocket caveat

WebSocket transport remains but only works with Bun. This is documented with a
runtime warning if used outside Bun.

### Not exported

- `keygen.ts`, `derive-public.ts` — these become standalone scripts or move to
  the scaffolder as optional tooling
- Transport implementation internals

## Build & Publish

### Library (`@futurity/plugins`)

- Build: `bun build` emitting ESM `.js` + `.d.ts` into `dist/`
- Exports in package.json point to `dist/`:
  ```json
  {
    "exports": {
      ".":         { "import": "./dist/index.js",   "types": "./dist/index.d.ts" },
      "./signing": { "import": "./dist/signing.js",  "types": "./dist/signing.d.ts" },
      "./cors":    { "import": "./dist/cors.js",     "types": "./dist/cors.d.ts" },
      "./oauth":   { "import": "./dist/oauth.js",    "types": "./dist/oauth.d.ts" }
    }
  }
  ```
- `files: ["dist"]` — only built output ships to npm
- Peer dependencies: `zod`, `@modelcontextprotocol/sdk` — consumers install
  their own versions for dedup and version control

### Scaffolder (`create-futurity-plugin`)

- Published to npm as `create-futurity-plugin`
- Usage: `bun create futurity-plugin my-plugin`
- Also handles `.` to scaffold into the current directory
- CLI logic:
  1. Accept project name arg (or `.` for cwd)
  2. Copy `template/` to target directory
  3. Substitute project name in `package.json`
  4. Run `bun install`
  5. Print success message with next steps

### Workspace root

- `workspaces` in root `package.json` pointing at `packages/*`
- Scripts: `build`, `test`, `check` that operate on both packages

## Scaffolder Template

What `bun create futurity-plugin my-plugin` generates:

```
my-plugin/
├── src/
│   └── index.ts
├── package.json
├── tsconfig.json
└── .gitignore
```

Starter `src/index.ts`:

```ts
import { mcp, t } from "@futurity/plugins";

const app = mcp({
  name: "my-plugin",
  version: "0.1.0",
});

app.tool("hello", {
  description: "Say hello",
  input: t.obj({ name: t.str }),
  handler: async ({ name }) => ({
    greeting: `Hello, ${name}!`,
  }),
});

await app.listen(3000);
```

## Migration

Existing plugin developers (who forked the repo) migrate by:

1. `bun add @futurity/plugins`
2. Change imports from relative paths to `@futurity/plugins`
3. Remove framework source files from their repo (keep only their plugin code)

This is a straightforward find-and-replace. All existing APIs remain the same —
only the import paths change, plus the new `app.fetch` option.
