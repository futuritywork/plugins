import { describe, expect, test } from "bun:test";
import { field, manifest, option, problems } from "./fixtures";

const at = (path: string) => `_meta["work.futurity/plugin"].credentials[0].${path}`;
const apiKey = field({ key: "api_key", kind: "plugin_secret", input: "password", header: "X-Api-Key" });

describe("Credential holders and methods", () => {
  test.each(["none", "plugin"] as const)("a %s-held option with method none and setup fields is accepted", (holder) => {
    const value = manifest([option({ holder, fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test.each(["none", "plugin"] as const)("a %s-held option with method secrets is rejected", (holder) => {
    const value = manifest([option({ holder, method: { type: "secrets" }, fields: [apiKey] })]);

    const errors = problems(value);

    expect(errors).toContain(at(`method: holder "${holder}" requires method "none"`));
  });

  test("a plugin-held option carrying a futurity_secret is rejected", () => {
    const secret = field({ key: "password", kind: "futurity_secret", header: undefined });
    const value = manifest([option({ holder: "plugin", fields: [secret] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields[0].kind: method "none" allows only setup fields')]);
  });

  test("method none with a plugin_secret field is rejected", () => {
    const value = manifest([option({ holder: "none", fields: [apiKey] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields[0].kind: method "none" allows only setup fields')]);
  });

  test("method secrets with a plugin_secret field is accepted", () => {
    const value = manifest([option({ holder: "user", method: { type: "secrets" }, fields: [{ ...apiKey, scope: "connect" }] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("method secrets with only setup fields is rejected", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [field()] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields: method "secrets" needs at least one plugin_secret field')]);
  });

  test("an org-held option with install-scoped fields is accepted", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [field(), apiKey] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an org-held option with a connect-scoped field is rejected", () => {
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [{ ...apiKey, scope: "connect" }] })]);

    const errors = problems(value);

    expect(errors).toEqual([at('fields[0].scope: holder "org" fields are entered once at install, so scope "connect" is not allowed')]);
  });
});
