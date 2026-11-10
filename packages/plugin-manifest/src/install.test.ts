import { describe, expect, test } from "bun:test";
import { field, option } from "./fixtures";
import { fieldsFor, installRequired } from "./helpers";

const userOAuth = {
  type: "oauth",
  grant: "authorization_code",
  authorizationUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  delivery: { header: "X-Access-Token" },
} as const;

describe("Org install", () => {
  test("an option with an install-scoped field needs an org install", () => {
    const value = option({ fields: [field({ scope: "install" })] });

    const needed = installRequired(value);

    expect(needed).toBe(true);
  });

  test("an oauth option on an admin-supplied client needs an org install even with no fields", () => {
    const value = option({ holder: "user", method: { ...userOAuth, client: "install" } });

    const needed = installRequired(value);

    expect(needed).toBe(true);
  });

  test("a user oauth option on the Futurity client with only connect fields needs no org install", () => {
    const value = option({ holder: "user", method: { ...userOAuth, client: "futurity" }, fields: [field({ scope: "connect" })] });

    const needed = installRequired(value);

    expect(needed).toBe(false);
  });

  test("the fields for a scope are the option's fields entered at that step", () => {
    const tenant = field({ key: "tenant", scope: "install" });
    const login = field({ key: "login", scope: "connect", header: "X-Login" });
    const value = option({ holder: "user", fields: [tenant, login] });

    const install = fieldsFor(value, "install");
    const connect = fieldsFor(value, "connect");

    expect(install).toEqual([tenant]);
    expect(connect).toEqual([login]);
  });
});
