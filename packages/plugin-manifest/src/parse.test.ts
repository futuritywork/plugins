import { describe, expect, test } from "bun:test";
import { field, manifest, option } from "./fixtures";
import { futurityExtension } from "./helpers";
import { parsePluginManifest } from "./parse";

describe("Manifest parsing", () => {
  test("a valid manifest given as JSON text comes back parsed with its Futurity extension", () => {
    const text = JSON.stringify(manifest());

    const result = parsePluginManifest(text);

    expect(result.success).toBe(true);
    if (result.success) expect(futurityExtension(result.manifest).developer.email).toBe("dev@example.com");
  });

  test("text that is not JSON is one root error", () => {
    const text = "{ not json";

    const result = parsePluginManifest(text);

    expect(result.success).toBe(false);
    if (!result.success) expect(result.errors).toHaveLength(1);
    if (!result.success) expect(result.errors[0]).toStartWith("(root): not valid JSON");
  });

  test("a non-object value is a root error", () => {
    const value = 42;

    const result = parsePluginManifest(value);

    expect(result.success).toBe(false);
    if (!result.success) expect(result.errors[0]).toStartWith("(root): ");
  });

  test("errors name the exact field path with the meta key quoted", () => {
    const value = manifest([option({ fields: [field(), field({ key: "region", header: "Bad Header" })] })]);

    const result = parsePluginManifest(value);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.errors[0]).toStartWith('_meta["work.futurity/plugin"].credentials[0].fields[1].header: ');
    }
  });

  test("unknown top-level server.json keys are dropped while the Futurity extension stays", () => {
    const value = { ...manifest(), $schema: "https://static.modelcontextprotocol.io/schemas/server.schema.json" };

    const result = parsePluginManifest(value);

    expect(result.success).toBe(true);
    if (result.success) expect(Object.keys(result.manifest)).not.toContain("$schema");
  });
});
