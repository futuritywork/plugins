import { describe, expect, test } from "bun:test";
import { FuturityIdentityClaimsSchema } from "./identity";

const now = 1_800_000_000;
const claims = {
  iss: "https://api.futurity.work",
  aud: "https://esb.example.com/mcp",
  sub: "user-1",
  org_id: "org-1",
  holder: "org",
  credential_option: "default",
  iat: now,
  exp: now + 300,
  jti: "token-1",
};

describe("Futurity identity token claims", () => {
  test("claims living five minutes are accepted", () => {
    const value = claims;

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.success).toBe(true);
  });

  test("claims living longer than five minutes are rejected", () => {
    const value = { ...claims, exp: now + 301 };

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.error?.issues[0]?.path).toEqual(["exp"]);
  });

  test("claims that expire before they were issued are rejected", () => {
    const value = { ...claims, exp: now - 1 };

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.success).toBe(false);
  });

  test("claims without an org are rejected", () => {
    const { org_id: _, ...value } = claims;

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.error?.issues[0]?.path).toEqual(["org_id"]);
  });

  test("claims naming an unknown holder are rejected", () => {
    const value = { ...claims, holder: "team" };

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.error?.issues[0]?.path).toEqual(["holder"]);
  });

  test("an audience list is accepted", () => {
    const value = { ...claims, aud: ["https://esb.example.com/mcp"] };

    const result = FuturityIdentityClaimsSchema.safeParse(value);

    expect(result.success).toBe(true);
  });
});
