# {{name}}

A Futurity MCP plugin. It serves tools over MCP and a manifest that tells
Futurity what the plugin is and which credentials it needs.

## Run it

```bash
cp .env.example .env
bun run dev             # http://localhost:3000/mcp
```

The manifest is served unsigned at `/.well-known/futurity/plugin`:

```bash
curl -i http://localhost:3000/.well-known/futurity/plugin
```

The SDK checks the manifest against the spec 5 rules when the server starts and
refuses to start if a rule is broken. It does the same for tools: every tool
must declare an `output` schema that can be advertised.

## Register it

1. Put the plugin on a public HTTPS address and set `PUBLIC_URL` to match.
   While you develop: `cloudflared tunnel --url http://localhost:3000`.
2. In Futurity, open **Atlas**, press **Add**, pick **Integration or MCP server URL**
   and enter the plugin's base URL (you need the **Manage systems**
   permission). The `/mcp` address the server prints works too. Futurity
   fetches and validates the manifest.
3. In the next dialog, pick the credential option, who can use it, and enter
   its fields, then press **Add**. Cancel there adds nothing.

A plugin your organization registers starts with every tool group, reads
included, on **Needs approval**, so each call asks first until an admin sets
read tools to **Allowed** on the system's page in Atlas.

Futurity pins the manifest it approved, and the tools the server listed. When
you change the manifest, admins see the change as a pending update and Futurity
keeps using the approved one, including its URL, until they approve it. A new
tool, or a changed description, argument or annotation, waits for an admin the
same way; a tool you stop serving is no longer called, and an admin approves its removal. A quick tunnel gets a new address on
every restart: give Futurity the new one with **Edit** on the plugin's row.

## Connect it

Every call to `/mcp` carries a short-lived identity token from Futurity in
`Authorization`. The SDK verifies it against `$FUTURITY_URL/oauth/jwks` and
refuses calls without a valid one. `FUTURITY_URL` must be the origin of the
Futurity API that calls you: `https://api-v4.futurity.work` in production,
`https://api-v4-staging.futurity.work` on staging. Each tool handler then receives:

- `org.id` and `user.id`: who is calling.
- `holder`: who holds the credential (`org`, `user`, `plugin` or `none`).
- `credentials`: the values of the fields the chosen credential option declares,
  read from their headers. An OAuth option's token is in `credentials.access_token`.

This plugin declares one organization API key, sent in `X-Api-Key`. Change the
`credentials` list in `src/index.ts` for per-person OAuth, setup fields such as
a tenant URL, or several options an admin can choose between.

Mark each tool with MCP annotations. Futurity groups tools as read
(`readOnlyHint: true`), delete (`destructiveHint: true`) or write (anything
else), and admins decide per group which run freely, which ask first, and which
are blocked.

## Where to edit

| File | What lives there |
| --- | --- |
| `src/index.ts` | The manifest and your tools |
