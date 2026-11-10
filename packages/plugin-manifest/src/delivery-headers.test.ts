import { describe, expect, test } from "bun:test";
import { field, manifest, option, problems } from "./fixtures";
import type { OAuthMethod } from "./schema";

const at = (path: string) => `_meta["work.futurity/plugin"].credentials[0].${path}`;
const HEADER_RULE = "must match ^X-[A-Za-z0-9-]+$ (Authorization is reserved for the Futurity identity token)";
const apiKey = field({ key: "api_key", kind: "plugin_secret", input: "password", header: "X-Api-Key" });

const tokenDelivery = (header: string): OAuthMethod => ({
  type: "oauth",
  grant: "client_credentials",
  tokenUrl: "https://auth.example.com/token",
  client: "futurity",
  delivery: { header },
});

const codeDelivery = (header: string): OAuthMethod => ({
  type: "oauth",
  grant: "authorization_code",
  authorizationUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  client: "futurity",
  delivery: { header },
});

describe("Delivery headers", () => {
  test("setup and plugin_secret fields with distinct X- headers are accepted", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [field(), apiKey] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a setup field without a header is accepted because only Futurity uses it", () => {
    const value = manifest([option({ fields: [field({ header: undefined })] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a header-less setup field can still fill an OAuth placeholder", () => {
    const companyId = field({ key: "company_id", header: undefined });
    const method: OAuthMethod = { ...tokenDelivery("X-Access-Token"), tokenParams: { company_id: "{company_id}" } };
    const value = manifest([option({ holder: "org", method, fields: [companyId] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a plugin_secret field without a header is rejected", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [{ ...apiKey, header: undefined }] })]);

    const errors = problems(value);

    expect(errors).toEqual([at("fields[0].header: a plugin_secret field needs a delivery header")]);
  });

  test("a futurity_secret field with a header is rejected because it never leaves Futurity", () => {
    const secret = field({ key: "client_secret", kind: "futurity_secret", header: "X-Client-Secret" });
    const value = manifest([option({ holder: "org", method: tokenDelivery("X-Access-Token"), fields: [secret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at("fields[0].header: a futurity_secret field is never delivered, so it takes no header")]);
  });

  test("a field delivered in Authorization is rejected", () => {
    const value = manifest([option({ fields: [field({ header: "Authorization" })] })]);

    const errors = problems(value);

    expect(errors).toEqual([at(`fields[0].header: ${HEADER_RULE}`)]);
  });

  test("a header with characters outside the token alphabet is rejected", () => {
    const value = manifest([option({ fields: [field({ header: "X-Tenant Id" })] })]);

    const errors = problems(value);

    expect(errors).toEqual([at(`fields[0].header: ${HEADER_RULE}`)]);
  });

  test("two fields sharing a header regardless of case are rejected", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [field(), { ...apiKey, header: "X-TENANT" }] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields[1].header: header "X-TENANT" is used twice in this option')]);
  });

  test("an OAuth token delivered in an X- header is accepted", () => {
    const value = manifest([option({ holder: "org", method: tokenDelivery("X-Access-Token") })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an OAuth token delivered in Authorization is rejected", () => {
    const value = manifest([option({ holder: "org", method: tokenDelivery("Authorization") })]);

    const errors = problems(value);

    expect(errors).toEqual([at(`method.delivery.header: ${HEADER_RULE}`)]);
  });

  test("an OAuth token header that collides with a setup field header is rejected", () => {
    const value = manifest([option({ holder: "org", method: tokenDelivery("X-Tenant"), fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.delivery.header: header "X-Tenant" is used twice in this option')]);
  });

  test("a token response field delivered in its own X- header is accepted", () => {
    const method: OAuthMethod = { ...tokenDelivery("X-Access-Token"), tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "X-Instance-Url" }] };
    const value = manifest([option({ holder: "org", method, fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a token response field sharing a setup field's header is rejected", () => {
    const method: OAuthMethod = { ...tokenDelivery("X-Access-Token"), tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "X-TENANT" }] };
    const value = manifest([option({ holder: "org", method, fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields[0].header: header "X-TENANT" is used twice in this option')]);
  });

  test("a token response field sharing the access token header is rejected", () => {
    const method: OAuthMethod = { ...tokenDelivery("X-Access-Token"), tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "X-Access-Token" }] };
    const value = manifest([option({ holder: "org", method })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.tokenResponseFields[0].header: header "X-Access-Token" is used twice in this option')]);
  });

  test("a token response field delivered in Authorization is rejected", () => {
    const method: OAuthMethod = { ...tokenDelivery("X-Access-Token"), tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "Authorization" }] };
    const value = manifest([option({ holder: "org", method })]);

    const errors = problems(value);

    expect(errors).toEqual([at(`method.tokenResponseFields[0].header: ${HEADER_RULE}`)]);
  });

  test("a callback query field sharing the access token header is rejected", () => {
    const method: OAuthMethod = { ...codeDelivery("X-Access-Token"), callbackQueryFields: [{ key: "realm_id", param: "realmId", header: "X-ACCESS-TOKEN" }] };
    const value = manifest([option({ holder: "user", method })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.callbackQueryFields[0].header: header "X-ACCESS-TOKEN" is used twice in this option')]);
  });

  test("a callback query field sharing a token response field's header is rejected", () => {
    const method: OAuthMethod = {
      ...codeDelivery("X-Access-Token"),
      tokenResponseFields: [{ key: "instance_url", path: "instance_url", header: "X-Realm-Id" }],
      callbackQueryFields: [{ key: "realm_id", param: "realmId", header: "X-Realm-Id" }],
    };
    const value = manifest([option({ holder: "user", method })]);

    const errors = problems(value);

    expect(errors).toEqual([at('method.callbackQueryFields[0].header: header "X-Realm-Id" is used twice in this option')]);
  });

  test("a callback query field delivered in Authorization is rejected", () => {
    const method: OAuthMethod = { ...codeDelivery("X-Access-Token"), callbackQueryFields: [{ key: "realm_id", param: "realmId", header: "Authorization" }] };
    const value = manifest([option({ holder: "user", method })]);

    const errors = problems(value);

    expect(errors).toEqual([at(`method.callbackQueryFields[0].header: ${HEADER_RULE}`)]);
  });
});
