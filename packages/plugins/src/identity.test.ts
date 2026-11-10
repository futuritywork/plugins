import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { FUTURITY_META_KEY, type CredentialOption, type PluginManifestInput } from "@futurity/plugin-manifest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { z } from "zod";
import { mcp, type McpApp } from "./app";

const ISSUER = "https://api.futurity.test";
const STAGING_ISSUER = "https://api.staging.futurity.test";
const REMOTE = "http://localhost/mcp";

const manifest: PluginManifestInput = {
  name: "work.futurity/esb",
  title: "ESB",
  description: "Sales from ESB Core",
  version: "1.0.0",
  remotes: [{ type: "streamable-http", url: REMOTE }],
  _meta: {
    [FUTURITY_META_KEY]: {
      specVersion: 5,
      developer: { email: "dev@example.com" },
      credentials: [
        {
          id: "org-key",
          label: "Organization API key",
          holder: "org",
          method: { type: "secrets" },
          fields: [
            { key: "tenant", label: "Tenant", kind: "setup", scope: "install", input: "text", header: "X-Tenant" },
            { key: "region", label: "Region", kind: "setup", scope: "install", input: "text", header: "X-Region", required: false },
            { key: "company_id", label: "Company", kind: "setup", scope: "install", input: "text" },
            { key: "api_key", label: "API key", kind: "plugin_secret", scope: "install", input: "password", header: "X-Api-Key" },
          ],
        },
        {
          id: "user-oauth",
          label: "Sign in with ESB",
          holder: "user",
          method: {
            type: "oauth",
            grant: "authorization_code",
            authorizationUrl: "https://auth.esb.test/authorize",
            tokenUrl: "https://auth.esb.test/token",
            client: "futurity",
            delivery: { header: "X-Esb-Token" },
            tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "X-Instance-Url" }],
            callbackQueryFields: [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }],
          },
          fields: [],
        },
      ],
    },
  },
};

let futurityKey: CryptoKey;
let stagingKey: CryptoKey;
let strangerKey: CryptoKey;
const jwksServers: ReturnType<typeof Bun.serve>[] = [];
let issuers: { issuer: string; jwksUrl: string }[];

/** Serves one public key as a JWKS, the way a Futurity deployment publishes /oauth/jwks. */
async function servedKey(): Promise<{ privateKey: CryptoKey; jwksUrl: string }> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "futurity-1", alg: "ES256", use: "sig" };
  const server = Bun.serve({ port: 0, fetch: () => Response.json({ keys: [jwk] }) });
  jwksServers.push(server);
  return { privateKey, jwksUrl: `http://localhost:${server.port}/oauth/jwks` };
}

beforeAll(async () => {
  const production = await servedKey();
  const staging = await servedKey();
  futurityKey = production.privateKey;
  stagingKey = staging.privateKey;
  ({ privateKey: strangerKey } = await generateKeyPair("ES256"));
  issuers = [
    { issuer: ISSUER, jwksUrl: production.jwksUrl },
    { issuer: STAGING_ISSUER, jwksUrl: staging.jwksUrl },
  ];
});

afterAll(() => {
  for (const server of jwksServers) server.stop(true);
});

type Claims = { sub?: string; org_id?: string; holder?: string; credential_option?: string; aud?: string; iss?: string; lifetime?: number };

async function identityToken(claims: Claims = {}, key: CryptoKey = futurityKey): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({
    org_id: claims.org_id ?? "org-1",
    holder: claims.holder ?? "org",
    credential_option: claims.credential_option ?? "org-key",
  })
    .setProtectedHeader({ alg: "ES256", kid: "futurity-1" })
    .setIssuer(claims.iss ?? ISSUER)
    .setAudience(claims.aud ?? REMOTE)
    .setSubject(claims.sub ?? "user-1")
    .setIssuedAt(now)
    .setExpirationTime(now + (claims.lifetime ?? 300))
    .setJti(crypto.randomUUID())
    .sign(key);
}

async function errorDescription(res: Response): Promise<string> {
  return ((await res.json()) as { error_description: string }).error_description;
}

const orgHeaders = { "X-Tenant": "acme", "X-Api-Key": "secret-key" };

function initialize(headers: Record<string, string>, url = REMOTE): Request {
  return new Request(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1.0.0" } },
    }),
  });
}

describe("Futurity identity on MCP requests", () => {
  let app: ReturnType<typeof buildApp>;
  const clients: Client[] = [];

  function buildApp() {
    const built = mcp({ manifest, futurity: { issuers } });
    built.tool("whoami", {
      output: z.looseObject({}),
      annotations: { readOnlyHint: true },
      handler: (_input, ctx) => ({ issuer: ctx.issuer, org: ctx.org.id, user: ctx.user.id, holder: ctx.holder, credentials: ctx.credentials }),
    });
    built.resource("esb://tenant", { fetch: (ctx) => ({ org: ctx.org.id, tenant: ctx.credentials.tenant }) });
    return built;
  }

  async function connect(headers: Record<string, string>): Promise<Client> {
    const client = new Client({ name: "futurity", version: "1.0.0" });
    clients.push(client);
    await client.connect(new StreamableHTTPClientTransport(new URL(REMOTE), {
      requestInit: { headers },
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));
    return client;
  }

  async function whoami(client: Client): Promise<unknown> {
    const result = await client.callTool({ name: "whoami" });
    return JSON.parse((result.content as { text: string }[])[0]!.text);
  }

  beforeAll(() => {
    app = buildApp();
  });

  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.close()));
  });

  afterAll(async () => {
    await app.stop();
  });

  test("a call with a valid token reaches the handler with the org, user, holder and declared credentials", async () => {
    const token = await identityToken();
    const client = await connect({ Authorization: `Bearer ${token}`, ...orgHeaders, "X-Region": "eu", "X-Undeclared": "ignored" });

    const caller = await whoami(client);

    expect(caller).toEqual({
      issuer: ISSUER,
      org: "org-1",
      user: "user-1",
      holder: "org",
      credentials: { tenant: "acme", region: "eu", api_key: "secret-key" },
    });
  });

  test("a resource read receives the same caller as a tool call", async () => {
    const token = await identityToken({ org_id: "org-7" });
    const client = await connect({ Authorization: `Bearer ${token}`, ...orgHeaders });

    const result = await client.readResource({ uri: "esb://tenant" });

    expect(result.contents).toEqual([{ uri: "esb://tenant", text: '{"org":"org-7","tenant":"acme"}' }]);
  });

  test("an optional credential header that is absent is left out of the credentials", async () => {
    const token = await identityToken();
    const client = await connect({ Authorization: `Bearer ${token}`, ...orgHeaders });

    const caller = await whoami(client);

    expect(caller).toMatchObject({ credentials: { tenant: "acme", api_key: "secret-key" } });
  });

  test("a setup field without a header is never read from the request", async () => {
    const token = await identityToken();
    const client = await connect({ Authorization: `Bearer ${token}`, ...orgHeaders, "X-Company-Id": "smuggled" });

    const caller = await whoami(client);

    expect(caller).toMatchObject({ credentials: { tenant: "acme", api_key: "secret-key" } });
    expect((caller as { credentials: Record<string, string> }).credentials).not.toHaveProperty("company_id");
  });

  test("an OAuth option hands the handler the access token, token response fields and callback query fields under their keys", async () => {
    const token = await identityToken({ holder: "user", credential_option: "user-oauth", sub: "user-2" });
    const client = await connect({ Authorization: `Bearer ${token}`, "X-Esb-Token": "esb-access", "X-Instance-Url": "https://acme.my.esb.test", "X-Realm-Id": "9130" });

    const caller = await whoami(client);

    expect(caller).toEqual({
      issuer: ISSUER,
      org: "org-1",
      user: "user-2",
      holder: "user",
      credentials: { access_token: "esb-access", instance_url: "https://acme.my.esb.test", realm_id: "9130" },
    });
  });

  test("an OAuth call missing a token response field header is refused with a JSON 400", async () => {
    const token = await identityToken({ holder: "user", credential_option: "user-oauth" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, "X-Esb-Token": "esb-access", "X-Realm-Id": "9130" }));

    expect(res.status).toBe(400);
    expect(await errorDescription(res)).toBe("Missing credential header X-Instance-Url");
  });

  test("an OAuth call missing a callback query field header is refused with a JSON 400", async () => {
    const token = await identityToken({ holder: "user", credential_option: "user-oauth" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, "X-Esb-Token": "esb-access", "X-Instance-Url": "https://acme.my.esb.test" }));

    expect(res.status).toBe(400);
    expect(await errorDescription(res)).toBe("Missing credential header X-Realm-Id");
  });

  test("a token from a second trusted deployment is verified against that deployment's keys", async () => {
    const token = await identityToken({ iss: STAGING_ISSUER }, stagingKey);
    const client = await connect({ Authorization: `Bearer ${token}`, ...orgHeaders });

    const caller = await whoami(client);

    expect(caller).toMatchObject({ issuer: STAGING_ISSUER, org: "org-1", user: "user-1" });
  });

  test("a token claiming one trusted issuer but signed with another deployment's key is refused", async () => {
    const token = await identityToken({ iss: ISSUER }, stagingKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toStartWith("Invalid Futurity identity token");
  });

  test("a session opened through one deployment is not found for the same ids through another", async () => {
    const first = await app.fetch(initialize({ Authorization: `Bearer ${await identityToken()}`, ...orgHeaders }));
    const sessionId = first.headers.get("mcp-session-id")!;
    await first.body?.cancel();
    const staging = await identityToken({ iss: STAGING_ISSUER }, stagingKey);

    const res = await app.fetch(new Request(REMOTE, {
      method: "GET",
      headers: { Accept: "text/event-stream", "Mcp-Session-Id": sessionId, Authorization: `Bearer ${staging}`, ...orgHeaders },
    }));

    expect(res.status).toBe(404);
  });

  test("a request without a token is refused with a JSON 401", async () => {
    const request = initialize(orgHeaders);

    const res = await app.fetch(request);

    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toStartWith("Bearer");
    expect(await res.json()).toEqual({ error: "unauthorized", error_description: "Missing Futurity identity token in Authorization" });
  });

  test("a token signed by a key outside the JWKS is refused", async () => {
    const token = await identityToken({}, strangerKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toStartWith("Invalid Futurity identity token");
  });

  test("a token from an issuer outside the trusted list is refused", async () => {
    const token = await identityToken({ iss: "https://evil.test" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe("Futurity identity token is not from a trusted issuer");
  });

  test("an app trusting no issuers cannot be built", () => {
    const build = () => mcp({ manifest, futurity: { issuers: [] } });

    expect(build).toThrow("futurity.issuers needs at least one trusted issuer.");
  });

  test("an OAuth option whose token response field is keyed access_token cannot be built", () => {
    const extension = manifest._meta[FUTURITY_META_KEY];
    const [orgKey, userOAuth] = extension.credentials;
    const method = { ...userOAuth!.method, tokenResponseFields: [{ key: "access_token", path: "access_token", header: "X-Raw-Token" }] };
    const clashing: PluginManifestInput = {
      ...manifest,
      _meta: { [FUTURITY_META_KEY]: { ...extension, credentials: [orgKey!, { ...userOAuth!, method } as CredentialOption] } },
    };

    const build = () => mcp({ manifest: clashing, futurity: { issuers } });

    expect(build).toThrow('Credential option "user-oauth" has a field named "access_token"');
  });

  test("an OAuth option whose callback query field is keyed access_token cannot be built", () => {
    const extension = manifest._meta[FUTURITY_META_KEY];
    const [orgKey, userOAuth] = extension.credentials;
    const method = { ...userOAuth!.method, callbackQueryFields: [{ key: "access_token", param: "code", header: "X-Raw-Code" }] };
    const clashing: PluginManifestInput = {
      ...manifest,
      _meta: { [FUTURITY_META_KEY]: { ...extension, credentials: [orgKey!, { ...userOAuth!, method } as CredentialOption] } },
    };

    const build = () => mcp({ manifest: clashing, futurity: { issuers } });

    expect(build).toThrow('Credential option "user-oauth" has a field named "access_token"');
  });

  test("an app listing one issuer twice cannot be built", () => {
    const build = () => mcp({ manifest, futurity: { issuers: [issuers[0]!, issuers[0]!] } });

    expect(build).toThrow(`Futurity issuer "${ISSUER}" is listed twice.`);
  });

  test("a token minted for another plugin's URL is refused even when the request claims that plugin's host", async () => {
    const other = "https://other.example.com/mcp";
    const token = await identityToken({ aud: other });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }, other));

    expect(res.status).toBe(401);
  });

  test("a token whose audience is the request's own URL rather than the manifest remote is refused", async () => {
    const token = await identityToken({ aud: "http://127.0.0.1/mcp" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }, "http://127.0.0.1/mcp"));

    expect(res.status).toBe(401);
  });

  test("a templated remote accepts a token whose audience is the template as written", async () => {
    const template = "https://{tenant}.esb.test/mcp";
    const extension = manifest._meta[FUTURITY_META_KEY];
    const orgOnly: PluginManifestInput = {
      ...manifest,
      remotes: [{ type: "streamable-http", url: template }],
      _meta: { [FUTURITY_META_KEY]: { ...extension, credentials: extension.credentials.slice(0, 1) } },
    };
    const templated = mcp({ manifest: orgOnly, futurity: { issuers } });
    const token = await identityToken({ aud: template });
    const resolvedToken = await identityToken({ aud: "https://acme.esb.test/mcp" });

    const accepted = await templated.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }, "https://acme.esb.test/mcp"));
    const refused = await templated.fetch(initialize({ Authorization: `Bearer ${resolvedToken}`, ...orgHeaders }, "https://acme.esb.test/mcp"));

    expect(accepted.status).toBe(200);
    expect(refused.status).toBe(401);
    await templated.stop();
  });

  test("a token living longer than five minutes is refused", async () => {
    const token = await identityToken({ lifetime: 3600 });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe("Futurity identity token has malformed claims: exp");
  });

  test("a token naming a credential option the manifest does not declare is refused", async () => {
    const token = await identityToken({ credential_option: "missing" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe('Credential option "missing" is not declared by this plugin');
  });

  test("a token whose holder disagrees with its credential option is refused", async () => {
    const token = await identityToken({ holder: "user" });

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
  });

  test("a call missing a required credential header is refused with a JSON 400", async () => {
    const token = await identityToken();

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, "X-Tenant": "acme" }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "missing_credential", error_description: "Missing credential header X-Api-Key" });
  });

  test("a session opened by one user is not found for another user", async () => {
    const first = await app.fetch(initialize({ Authorization: `Bearer ${await identityToken()}`, ...orgHeaders }));
    const sessionId = first.headers.get("mcp-session-id")!;
    await first.body?.cancel();

    const res = await app.fetch(new Request(REMOTE, {
      method: "GET",
      headers: { Accept: "text/event-stream", "Mcp-Session-Id": sessionId, Authorization: `Bearer ${await identityToken({ sub: "user-9" })}`, ...orgHeaders },
    }));

    expect(res.status).toBe(404);
  });

  test("the manifest is served without a token", async () => {
    const request = new Request("http://localhost/.well-known/futurity/plugin");

    const res = await app.fetch(request);

    expect(res.status).toBe(200);
  });

  test("an app verifying identity refuses the WebSocket transport", async () => {
    const built = mcp({ manifest, futurity: { issuers } });

    const listening = built.listen(0, "websocket");

    await expect(listening).rejects.toThrow("WebSocket transport carries no Futurity identity");
  });
});

describe("Futurity identity from a wildcard issuer", () => {
  let subdomainKey: CryptoKey;
  let port: number;
  let app: McpApp;

  beforeAll(async () => {
    const { privateKey, jwksUrl } = await servedKey();
    subdomainKey = privateKey;
    port = Number(new URL(jwksUrl).port);
    app = mcp({ manifest, futurity: { issuers: [...issuers, { issuer: `http://*.localhost:${port}`, jwksUrl: "/oauth/jwks" }] } });
  });

  afterAll(async () => {
    await app.stop();
  });

  test("a token from a subdomain issuer is verified against that origin's /oauth/jwks", async () => {
    const token = await identityToken({ iss: `http://tunnel-1.localhost:${port}` }, subdomainKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(200);
    await res.body?.cancel();
  });

  test("a lookalike domain that only contains the trusted host is refused", async () => {
    const token = await identityToken({ iss: `http://tunnel-1.localhost.evil.test:${port}` }, subdomainKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe("Futurity identity token is not from a trusted issuer");
  });

  test("a subdomain issuer with another scheme is refused", async () => {
    const token = await identityToken({ iss: `https://tunnel-1.localhost:${port}` }, subdomainKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe("Futurity identity token is not from a trusted issuer");
  });

  test("a subdomain issuer with a path is refused", async () => {
    const token = await identityToken({ iss: `http://tunnel-1.localhost:${port}/api` }, subdomainKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toBe("Futurity identity token is not from a trusted issuer");
  });

  test("a token under a matching subdomain signed by a key outside that origin's JWKS is refused", async () => {
    const token = await identityToken({ iss: `http://tunnel-2.localhost:${port}` }, strangerKey);

    const res = await app.fetch(initialize({ Authorization: `Bearer ${token}`, ...orgHeaders }));

    expect(res.status).toBe(401);
    expect(await errorDescription(res)).toStartWith("Invalid Futurity identity token");
  });

  test("a wildcard issuer whose keys are a full URL cannot be built", () => {
    const build = () => mcp({ manifest, futurity: { issuers: [{ issuer: "https://*.futurity.work", jwksUrl: "https://api.futurity.work/oauth/jwks" }] } });

    expect(build).toThrow('Futurity issuer "https://*.futurity.work" needs a jwksUrl path such as "/oauth/jwks".');
  });
});

describe("Apps built without Futurity identity", () => {
  test("a call without a token reaches the handler with no org, user or credentials", async () => {
    const app = mcp({ manifest, futurity: false });
    app.tool("whoami", { output: z.looseObject({}), handler: (_input, ctx) => ({ issuer: ctx.issuer, org: ctx.org, user: ctx.user, holder: ctx.holder, credentials: ctx.credentials }) });
    const client = new Client({ name: "local", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(REMOTE), {
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));

    const result = await client.callTool({ name: "whoami" });

    expect(result.content).toEqual([{ type: "text", text: '{"issuer":null,"org":null,"user":null,"holder":null,"credentials":{}}' }]);
    await client.close();
    await app.stop();
  });
});
