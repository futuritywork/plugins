import { afterEach, describe, expect, test } from "bun:test";
import { FUTURITY_META_KEY, type PluginManifestInput } from "@futurity/plugin-manifest";
import { mcp } from "./app";
import { cors } from "./cors";

const manifest: PluginManifestInput = {
  name: "work.futurity/cors",
  title: "CORS",
  description: "A plugin under test",
  version: "1.0.0",
  remotes: [{ type: "streamable-http", url: "http://localhost/mcp" }],
  _meta: {
    [FUTURITY_META_KEY]: {
      specVersion: 5,
      developer: { email: "dev@example.com" },
      credentials: [{ id: "public", label: "Public", holder: "none", method: { type: "none" }, fields: [] }],
    },
  },
};

const preflight = (origin: string) =>
  new Request("http://localhost/mcp", { method: "OPTIONS", headers: { Origin: origin } });

describe("CORS origins", () => {
  let app = mcp({ manifest, futurity: false });

  afterEach(async () => {
    await app.stop();
  });

  test("a listed origin is echoed back", async () => {
    app = mcp({ manifest, futurity: false }).use(cors({ origins: ["https://app.futurity.work"] }));

    const res = await app.fetch(preflight("https://app.futurity.work"));

    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.futurity.work");
  });

  test("an unlisted origin gets no allow-origin header", async () => {
    app = mcp({ manifest, futurity: false }).use(cors({ origins: ["https://app.futurity.work"] }));

    const res = await app.fetch(preflight("https://evil.example.com"));

    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  test("a listed origin with credentials is echoed with allow-credentials", async () => {
    app = mcp({ manifest, futurity: false }).use(cors({ origins: ["https://app.futurity.work"], credentials: true }));

    const res = await app.fetch(preflight("https://app.futurity.work"));

    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.futurity.work");
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
  });

  test("an unlisted origin with credentials configured gets no CORS headers at all", async () => {
    app = mcp({ manifest, futurity: false }).use(cors({ origins: ["https://app.futurity.work"], credentials: true }));

    const res = await app.fetch(preflight("https://evil.example.com"));

    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  test("with no origins configured no caller gets CORS headers", async () => {
    app = mcp({ manifest, futurity: false }).use(cors({ credentials: true }));

    const res = await app.fetch(preflight("https://app.futurity.work"));

    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("access-control-allow-methods")).toBeNull();
  });

  test("a wildcard origin is refused when the policy is built", () => {
    const build = () => cors({ origins: ["*"], credentials: true });

    expect(build).toThrow('"*" is not allowed');
  });
});
