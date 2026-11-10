import { describe, expect, test } from "bun:test";
import { field, manifest, option, problems } from "./fixtures";
import { placeholders } from "./placeholders";
import type { OAuthMethod } from "./schema";

const at = (path: string) => `_meta["work.futurity/plugin"].credentials[0].${path}`;
const companyId = field({ key: "company_id", header: "X-Company-Id" });

function authorizationCode(overrides: Partial<OAuthMethod> = {}): OAuthMethod {
  return {
    type: "oauth",
    grant: "authorization_code",
    authorizationUrl: "https://{tenant}.example.com/authorize",
    tokenUrl: "https://{tenant}.example.com/token",
    client: "futurity",
    delivery: { header: "X-Access-Token" },
    ...overrides,
  } as OAuthMethod;
}

function clientCredentials(overrides: Partial<OAuthMethod> = {}): OAuthMethod {
  return {
    type: "oauth",
    grant: "client_credentials",
    tokenUrl: "https://{tenant}.example.com/token",
    client: "futurity",
    delivery: { header: "X-Access-Token" },
    ...overrides,
  } as OAuthMethod;
}

describe("Field placeholders", () => {
  test("the distinct placeholder names of a text come back in order of first use", () => {
    const text = "https://{tenant}.example.com/{region}/{tenant}";

    const names = placeholders(text);

    expect(names).toEqual(["tenant", "region"]);
  });

  test("a text without braces has no placeholders", () => {
    const text = "https://example.com/token";

    const names = placeholders(text);

    expect(names).toEqual([]);
  });

  test("placeholders in the token URL and token params that name setup fields are accepted", () => {
    const method = clientCredentials({ tokenParams: { company_id: "{company_id}" } });
    const value = manifest([option({ holder: "org", method, fields: [field(), companyId] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a token URL placeholder with no matching field is rejected", () => {
    const value = manifest([option({ holder: "org", method: clientCredentials(), fields: [companyId] })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.tokenUrl: placeholder {tenant} does not name an install-scoped setup field of this option")]);
  });

  test("an auth param placeholder naming a secret rather than a setup field is rejected", () => {
    const secret = field({ key: "client_secret", kind: "futurity_secret", header: undefined });
    const method = clientCredentials({ tokenUrl: "https://auth.example.com/token", authParams: { secret: "{client_secret}" } });
    const value = manifest([option({ holder: "org", method, fields: [secret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.authParams.secret: placeholder {client_secret} does not name an install-scoped setup field of this option")]);
  });

  test("a remote URL placeholder named by a setup field in every option is accepted", () => {
    const value = manifest([option({ fields: [field()] }), option({ id: "second", fields: [field()] })], {
      remotes: [{ type: "streamable-http", url: "https://{tenant}.example.com/mcp" }],
    });

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a remote URL placeholder missing from one option is rejected for that option", () => {
    const value = manifest([option({ fields: [field()] }), option({ id: "second" })], {
      remotes: [{ type: "streamable-http", url: "https://{tenant}.example.com/mcp" }],
    });

    const errors = problems(value);

    expect(errors).toEqual(['remotes[0].url: placeholder {tenant} does not name an install-scoped setup field of credential option "second"']);
  });

  test("a member-held option whose OAuth URLs name an install-scoped field an admin sets is accepted", () => {
    const value = manifest([option({ holder: "user", method: authorizationCode(), fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an OAuth URL placeholder naming a connect-scoped field a member types is rejected", () => {
    const memberTenant = field({ scope: "connect" });
    const value = manifest([option({ holder: "user", method: authorizationCode(), fields: [memberTenant] })]);

    const errors = problems(value);

    expect(errors).toEqual([
      at("method.tokenUrl: placeholder {tenant} does not name an install-scoped setup field of this option"),
      at("method.authorizationUrl: placeholder {tenant} does not name an install-scoped setup field of this option"),
    ]);
  });

  test("a token param placeholder naming a connect-scoped field is rejected", () => {
    const memberCompany = field({ key: "company_id", scope: "connect", header: "X-Company-Id" });
    const method = authorizationCode({ tokenParams: { company_id: "{company_id}" } });
    const value = manifest([option({ holder: "user", method, fields: [field(), memberCompany] })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.tokenParams.company_id: placeholder {company_id} does not name an install-scoped setup field of this option")]);
  });

  test("a remote URL placeholder naming a connect-scoped field is rejected", () => {
    const memberTenant = field({ scope: "connect" });
    const value = manifest([option({ holder: "user", fields: [memberTenant] })], {
      remotes: [{ type: "streamable-http", url: "https://{tenant}.example.com/mcp" }],
    });

    const errors = problems(value);

    expect(errors).toEqual(['remotes[0].url: placeholder {tenant} does not name an install-scoped setup field of credential option "default"']);
  });
});
