import { describe, expect, test } from "bun:test";
import { field, manifest, option, problems } from "./fixtures";
import { FUTURITY_META_KEY } from "./schema";

describe("Manifest shape", () => {
  test("a manifest with a reverse-DNS name, semver version and one remote is accepted", () => {
    const value = manifest();

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a name without a namespace slash is rejected", () => {
    const value = manifest(undefined, { name: "esb" });

    const errors = problems(value);

    expect(errors).toEqual(["name: must be a reverse-DNS id such as work.futurity/esb"]);
  });

  test("a version that is not x.y.z is rejected", () => {
    const value = manifest(undefined, { version: "1.0" });

    const errors = problems(value);

    expect(errors).toEqual(["version: must be semver x.y.z"]);
  });

  test("a manifest with two remotes is rejected", () => {
    const remote = { type: "streamable-http" as const, url: "https://esb.example.com/mcp" };
    const value = { ...manifest(), remotes: [remote, remote] };

    const errors = problems(value);

    expect(errors.some((error) => error.startsWith("remotes"))).toBe(true);
  });

  test("a remote with a transport other than streamable-http is rejected", () => {
    const value = { ...manifest(), remotes: [{ type: "sse", url: "https://esb.example.com/sse" }] };

    const errors = problems(value);

    expect(errors.some((error) => error.startsWith("remotes[0].type"))).toBe(true);
  });

  test("an extension at spec version 4 is rejected", () => {
    const value = manifest();
    value._meta[FUTURITY_META_KEY].specVersion = 4 as 5;

    const errors = problems(value);

    expect(errors[0]).toStartWith('_meta["work.futurity/plugin"].specVersion');
  });

  test("an extension with no credential options is rejected", () => {
    const value = manifest([]);

    const errors = problems(value);

    expect(errors).toEqual(['_meta["work.futurity/plugin"].credentials: declare at least one credential option']);
  });

  test("a developer without a valid email is rejected", () => {
    const value = manifest();
    value._meta[FUTURITY_META_KEY].developer = { email: "not-an-email" };

    const errors = problems(value);

    expect(errors[0]).toStartWith('_meta["work.futurity/plugin"].developer.email');
  });

  test("an extension carrying a retired key such as dangerLevel is rejected", () => {
    const value = manifest();
    Object.assign(value._meta[FUTURITY_META_KEY], { dangerLevel: "read" });

    const errors = problems(value);

    expect(errors[0]).toContain("dangerLevel");
  });

  test("two credential options with one id are rejected", () => {
    const value = manifest([option(), option()]);

    const errors = problems(value);

    expect(errors).toEqual(['_meta["work.futurity/plugin"].credentials[1].id: credential option id "default" is used twice']);
  });

  test("two options with distinct ids are accepted", () => {
    const value = manifest([option(), option({ id: "other" })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("two fields sharing a key in one option are rejected", () => {
    const value = manifest([option({ fields: [field(), field({ header: "X-Other" })] })]);

    const errors = problems(value);

    expect(errors).toEqual(['_meta["work.futurity/plugin"].credentials[0].fields[1].key: field key "tenant" is used twice in this option']);
  });

  test("an x509-keypair secret with a secondaryKey is accepted", () => {
    const keypair = field({ key: "private_key", secondaryKey: "certificate", kind: "futurity_secret", input: "x509-keypair", header: undefined });
    const value = manifest([option({ holder: "org", method: { type: "secrets" }, fields: [keypair, field({ key: "api_key", kind: "plugin_secret", header: "X-Api-Key" })] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an x509-keypair field without a secondaryKey is rejected", () => {
    const value = manifest([option({ fields: [field({ input: "x509-keypair" })] })]);

    const errors = problems(value);

    expect(errors).toEqual(['_meta["work.futurity/plugin"].credentials[0].fields[0].secondaryKey: an x509-keypair field needs a secondaryKey']);
  });

  test("a text field with a secondaryKey is rejected", () => {
    const value = manifest([option({ fields: [field({ secondaryKey: "second" })] })]);

    const errors = problems(value);

    expect(errors).toEqual(['_meta["work.futurity/plugin"].credentials[0].fields[0].secondaryKey: only an x509-keypair field takes a secondaryKey']);
  });

  test("display hints on fields and setup steps on an option are accepted", () => {
    const tenant = field({ placeholder: "acme", help: "The subdomain before .esb.example.com" });
    const value = manifest([option({ fields: [tenant], setupSteps: ["Open ESB Admin", "Copy the tenant name"] })]);

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an option with an empty list of setup steps is rejected", () => {
    const value = manifest([option({ setupSteps: [] })]);

    const errors = problems(value);

    expect(errors).toHaveLength(1);
    expect(errors[0]).toStartWith('_meta["work.futurity/plugin"].credentials[0].setupSteps:');
  });

  test("a field placeholder that is not text is rejected", () => {
    const value = manifest([option({ fields: [field({ placeholder: 42 as unknown as string })] })]);

    const errors = problems(value);

    expect(errors).toHaveLength(1);
    expect(errors[0]).toStartWith('_meta["work.futurity/plugin"].credentials[0].fields[0].placeholder:');
  });
});
