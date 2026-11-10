import { describe, expect, test } from "bun:test";
import { field, manifest, option, problems } from "./fixtures";
import type { OAuthMethod } from "./schema";

const at = (path: string) => `_meta["work.futurity/plugin"].credentials[0].${path}`;

function oauth(overrides: Partial<OAuthMethod> = {}): OAuthMethod {
  return {
    type: "oauth",
    grant: "authorization_code",
    authorizationUrl: "https://auth.example.com/authorize",
    tokenUrl: "https://auth.example.com/token",
    client: "futurity",
    delivery: { header: "X-Access-Token" },
    ...overrides,
  } as OAuthMethod;
}

const clientId = field({ key: "client_id", kind: "setup", scope: "install", header: "X-Client-Id" });
const clientSecret = field({ key: "client_secret", kind: "futurity_secret", scope: "install", input: "password", header: undefined });
const privateKey = field({ key: "private_key", kind: "futurity_secret", scope: "install", input: "textarea", header: undefined });

describe("OAuth credential methods", () => {
  test("a user-held authorization_code option on the Futurity client is accepted", () => {
    const value = manifest([option({ holder: "user", method: oauth() })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an oauth option with a plugin_secret field is rejected", () => {
    const secret = field({ key: "api_key", kind: "plugin_secret", header: "X-Api-Key", scope: "connect" });
    const value = manifest([option({ holder: "user", method: oauth(), fields: [secret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields[0].kind: method "oauth" does not allow plugin_secret fields')]);
  });

  test("an install client with install-scoped client_id and client_secret is accepted", () => {
    const value = manifest([option({ holder: "org", method: oauth({ grant: "client_credentials", authorizationUrl: undefined, client: "install" }), fields: [clientId, clientSecret] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an install client missing its client_secret is rejected", () => {
    const value = manifest([option({ holder: "org", method: oauth({ grant: "client_credentials", authorizationUrl: undefined, client: "install" }), fields: [clientId] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields: client "install" needs an install-scoped futurity_secret field "client_secret"')]);
  });

  test("an install client whose client_id is connect-scoped is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ client: "install" }), fields: [{ ...clientId, scope: "connect" }, clientSecret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields: client "install" needs an install-scoped setup field "client_id"')]);
  });

  test.each(["jwt_bearer", "saml_bearer"] as const)("an install client on %s with a private key secret is accepted", (grant) => {
    const value = manifest([option({ holder: "org", method: oauth({ grant, authorizationUrl: undefined, client: "install" }), fields: [privateKey] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an install client on saml_bearer with an x509-keypair secret is accepted", () => {
    const keypair = field({ key: "signing", secondaryKey: "certificate", kind: "futurity_secret", input: "x509-keypair", header: undefined });
    const value = manifest([option({ holder: "org", method: oauth({ grant: "saml_bearer", authorizationUrl: undefined, client: "install" }), fields: [keypair] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test.each(["jwt_bearer", "saml_bearer"] as const)("an install client on %s without a private key is rejected", (grant) => {
    const value = manifest([option({ holder: "org", method: oauth({ grant, authorizationUrl: undefined, client: "install" }), fields: [clientId, clientSecret] })]);

    const errors = problems(value);

    expect(errors).toEqual([
      at(`fields: client "install" with the ${grant} grant needs an install-scoped futurity_secret private key (key "private_key" or input "x509-keypair")`),
    ]);
  });

  test("a user-held jwt_bearer option acting as the user is accepted", () => {
    const value = manifest([option({ holder: "user", method: oauth({ grant: "jwt_bearer", authorizationUrl: undefined, actsAs: "user" }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a user-held jwt_bearer option without actsAs is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ grant: "jwt_bearer", authorizationUrl: undefined }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.actsAs: holder "user" with the jwt_bearer grant requires actsAs "user"')]);
  });

  test("a user-held client_credentials option is rejected because it cannot act as the user", () => {
    const value = manifest([option({ holder: "user", method: oauth({ grant: "client_credentials", authorizationUrl: undefined }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.actsAs: holder "user" with the client_credentials grant requires actsAs "user"')]);
  });

  test("actsAs on the authorization_code grant is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ actsAs: "user" }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.actsAs: actsAs applies only to the jwt_bearer and saml_bearer grants")]);
  });

  test("mcp_authorization delivery on a dcr client is accepted", () => {
    const value = manifest([option({ holder: "user", method: oauth({ client: "dcr", delivery: "mcp_authorization" }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("mcp_authorization delivery on the Futurity client is accepted for a vendor server with no dynamic registration", () => {
    const value = manifest([option({ holder: "user", method: oauth({ delivery: "mcp_authorization", scopes: ["repo", "read:org"] }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("mcp_authorization delivery on an install client with the org's client_id and client_secret is accepted", () => {
    const value = manifest([option({ holder: "user", method: oauth({ client: "install", delivery: "mcp_authorization" }), fields: [{ ...clientId, header: undefined }, clientSecret] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("mcp_authorization delivery on an install client without its client_secret is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ client: "install", delivery: "mcp_authorization" }), fields: [{ ...clientId, header: undefined }] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields: client "install" needs an install-scoped futurity_secret field "client_secret"')]);
  });

  test("token response fields on mcp_authorization delivery with an install client are rejected", () => {
    const tokenResponseFields = [{ key: "instance_url", path: "instance_url", header: "X-Instance-Url" }];
    const value = manifest([option({ holder: "user", method: oauth({ client: "install", delivery: "mcp_authorization", tokenResponseFields }), fields: [{ ...clientId, header: undefined }, clientSecret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields: delivery "mcp_authorization" sends nothing from Futurity, so it takes no tokenResponseFields')]);
  });

  test("an authorization_code grant without an authorizationUrl is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ authorizationUrl: undefined }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.authorizationUrl: the authorization_code grant needs an authorizationUrl")]);
  });

  test("a client_credentials grant with an authorizationUrl is rejected", () => {
    const value = manifest([option({ holder: "org", method: oauth({ grant: "client_credentials" }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.authorizationUrl: only the authorization_code grant takes an authorizationUrl")]);
  });

  test.each(["form", "json"] as const)("a token request encoded as %s is accepted", (encoding) => {
    const value = manifest([option({ holder: "user", method: oauth({ tokenRequest: { encoding } }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a token request with an unknown encoding is rejected", () => {
    const value = manifest([option({ holder: "user", method: oauth({ tokenRequest: { encoding: "xml" as "json" } }) })]);

    const errors = problems(value);

    expect(errors).toHaveLength(1);
    expect(errors[0]).toStartWith(at("method.tokenRequest.encoding:"));
  });

  test("an authorization_code option that turns PKCE off is accepted", () => {
    const value = manifest([option({ holder: "user", method: oauth({ pkce: false }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("pkce on a grant without an authorization step is rejected", () => {
    const value = manifest([option({ holder: "org", method: oauth({ grant: "client_credentials", authorizationUrl: undefined, pkce: false }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.pkce: only the authorization_code grant takes pkce")]);
  });

  test("token response fields with distinct keys, dotted paths and headers are accepted", () => {
    const tokenResponseFields = [
      { key: "instance_url", path: "instance_url", header: "X-Instance-Url" },
      { key: "team_id", path: "team.id", header: "X-Team-Id" },
    ];
    const value = manifest([option({ holder: "user", method: oauth({ tokenResponseFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a token response field reusing another field's key is rejected", () => {
    const tenant = field({ key: "instance_url", header: "X-Tenant" });
    const tokenResponseFields = [{ key: "instance_url", path: "instance_url", header: "X-Instance-Url" }];
    const value = manifest([option({ holder: "user", method: oauth({ tokenResponseFields }), fields: [tenant] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields[0].key: field key "instance_url" is used twice in this option')]);
  });

  test("two token response fields sharing a key are rejected", () => {
    const tokenResponseFields = [
      { key: "realm", path: "realmId", header: "X-Realm" },
      { key: "realm", path: "realm_id", header: "X-Realm-Id" },
    ];
    const value = manifest([option({ holder: "user", method: oauth({ tokenResponseFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields[1].key: field key "realm" is used twice in this option')]);
  });

  test("a token response path that is not dotted property names is rejected", () => {
    const tokenResponseFields = [{ key: "instance_url", path: "$.instance_url", header: "X-Instance-Url" }];
    const value = manifest([option({ holder: "user", method: oauth({ tokenResponseFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.tokenResponseFields[0].path: must be a dotted path of property names, e.g. instance_url")]);
  });

  test("token response fields on mcp_authorization delivery are rejected", () => {
    const tokenResponseFields = [{ key: "instance_url", path: "instance_url", header: "X-Instance-Url" }];
    const value = manifest([option({ holder: "user", method: oauth({ client: "dcr", delivery: "mcp_authorization", tokenResponseFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields: delivery "mcp_authorization" sends nothing from Futurity, so it takes no tokenResponseFields')]);
  });

  test("callback query fields on an authorization_code option with header delivery are accepted", () => {
    const callbackQueryFields = [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "user", method: oauth({ callbackQueryFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("callback query fields on a grant without an authorization redirect are rejected", () => {
    const callbackQueryFields = [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "org", method: oauth({ grant: "client_credentials", authorizationUrl: undefined, callbackQueryFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at("method.callbackQueryFields: only the authorization_code grant has an authorization redirect, so only it takes callbackQueryFields")]);
  });

  test("callback query fields on mcp_authorization delivery are rejected", () => {
    const callbackQueryFields = [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "user", method: oauth({ client: "dcr", delivery: "mcp_authorization", callbackQueryFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.callbackQueryFields: delivery "mcp_authorization" sends nothing from Futurity, so it takes no callbackQueryFields')]);
  });

  test("a callback query field reusing a token response field's key is rejected", () => {
    const tokenResponseFields = [{ key: "realm_id", path: "realmId", header: "X-Realm" }];
    const callbackQueryFields = [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "user", method: oauth({ tokenResponseFields, callbackQueryFields }) })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.callbackQueryFields[0].key: field key "realm_id" is used twice in this option')]);
  });

  test("a callback query field reusing a setup field's key is rejected", () => {
    const realm = field({ key: "realm_id", header: "X-Tenant" });
    const callbackQueryFields = [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "user", method: oauth({ callbackQueryFields }), fields: [realm] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.callbackQueryFields[0].key: field key "realm_id" is used twice in this option')]);
  });

  test("a callback query field with an empty param is rejected", () => {
    const callbackQueryFields = [{ key: "realm_id", param: "", header: "X-Realm-Id" }];
    const value = manifest([option({ holder: "user", method: oauth({ callbackQueryFields }) })]);

    const errors = problems(value);

    expect(errors).toHaveLength(1);
    expect(errors[0]).toStartWith(at("method.callbackQueryFields[0].param: "));
  });
});
