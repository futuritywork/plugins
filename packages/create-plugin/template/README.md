# {{name}}

A Futurity MCP plugin. It serves tools over MCP, and a signed manifest that
Futurity checks before it trusts them.

## Run it

```bash
cp .env.example .env
bun run keygen          # writes a keypair; put the private half in .env
bun run dev             # http://localhost:3000/mcp
```

With `FUTURITY_SIGNING_KEY` set, the manifest is served at
`/.well-known/futurity/plugin` with its detached signature in the
`X-Futurity-Signature` header:

```bash
curl -i http://localhost:3000/.well-known/futurity/plugin
```

## Register it

1. Put the plugin on a public HTTPS address and set `PUBLIC_URL` to match.
   While you develop: `cloudflared tunnel --url http://localhost:3000`.
2. In Corint, open **Integrations → Developer Tools → Add**, paste the base
   URL (not the `/mcp` path), and click **Discover**.
3. Paste the public key from `bun run keygen` and click **Register Plugin**.
   The signature is verified at that moment.

Registration needs plugin developer access on your account. Futurity
re-verifies the manifest every 24 hours, so keep the address stable.

## Connect it

This plugin declares the `client_credentials` grant, so one set of credentials
belongs to the whole organization and an administrator saves them once. They
land at your `/oauth/token` endpoint in `src/auth.ts`; whatever `access_token`
you return there arrives on every tool call as `X-Plugin-Access-Token`, and
`requireAccessToken()` hands it to your handler.

Other grants — per-person OAuth, SAML bearer, an API key, or your own auth
flow — are in the plugin authentication reference.

## Where to edit

| File | What lives there |
| --- | --- |
| `src/index.ts` | The manifest, the middleware wiring, and your tools |
| `src/auth.ts` | The token endpoint and the per-request credentials |
| `scripts/keygen.ts` | The Ed25519 keypair generator |
