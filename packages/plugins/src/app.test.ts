import { test, expect, describe, afterEach, beforeEach } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { mcp } from "./app";
import { generateKeyPair, verifyPayload } from "./signing";
import type { PluginManifestOptions } from "./pluginManifest";

const signingKeys = generateKeyPair();
const pluginManifest: PluginManifestOptions = {
  pluginId: "test",
  developerEmail: "developer@example.com",
  name: "Test",
  version: "1.0.0",
  mcpUrl: "http://localhost/mcp",
  auth: { type: "none" },
  signingKey: signingKeys.privateKey,
};

describe("McpApp tool outputs", () => {
  let app: ReturnType<typeof mcp>;
  let client: Client;

  beforeEach(() => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });
    client = new Client({ name: "test-client", version: "1.0.0" });
  });

  afterEach(async () => {
    await client.close();
    await app.stop();
  });

  /** Connects through the public fetch API without opening a network listener. */
  async function connect() {
    await client.connect(new StreamableHTTPClientTransport(new URL("http://localhost/mcp"), {
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));
  }

  test("advertises object outputs and returns structured content alongside JSON text", async () => {
    app.tool("add", {
      input: z.object({ a: z.number(), b: z.number() }),
      output: z.object({ sum: z.number().describe("The sum") }),
      dangerLevel: "read",
      handler: ({ a, b }, { signal }) => {
        expect(signal).toBeInstanceOf(AbortSignal);
        expect(signal.aborted).toBe(false);
        return { sum: a + b };
      },
    });
    await connect();
    const { tools } = await client.listTools();
    expect(tools[0]?.outputSchema).toMatchObject({
      type: "object",
      properties: { sum: { type: "number", description: "The sum" } },
      required: ["sum"],
    });
    expect(tools[0]?.annotations).toEqual({ readOnlyHint: true, destructiveHint: false });
    expect(tools[0]?._meta).toEqual({ "futurity:dangerLevel": "read" });
    expect(await client.callTool({ name: "add", arguments: { a: 2, b: 3 } })).toEqual({
      content: [{ type: "text", text: '{"sum":5}' }],
      structuredContent: { sum: 5 },
    });
  });

  test.each([false, true])("preserves cancellation context with input schema: %s", async (withInput) => {
    const started = Promise.withResolvers<AbortSignal>();
    const cancelled = Promise.withResolvers<void>();
    app.tool("wait", {
      ...(withInput && { input: z.object({}) }),
      output: z.object({ done: z.boolean() }),
      handler: async (_input, { signal }) => {
        started.resolve(signal);
        await new Promise<void>((resolve) => signal.addEventListener("abort", () => {
          cancelled.resolve();
          resolve();
        }, { once: true }));
        return { done: true };
      },
    });
    await connect();
    const controller = new AbortController();
    const call = client.callTool({ name: "wait", arguments: {} }, undefined, { signal: controller.signal });
    const outcome = call.catch(error => error);
    const signal = await started.promise;
    expect(signal.aborted).toBe(false);
    controller.abort();
    expect(await outcome).toBeInstanceOf(Error);
    await cancelled.promise;
    expect(signal.aborted).toBe(true);
  });

  test("supports output schemas on tools without an input schema", async () => {
    app.tool("ping", {
      output: z.object({ status: z.literal("ok") }),
      handler: (_input, { signal }) => {
        expect(signal).toBeInstanceOf(AbortSignal);
        return { status: "ok" as const };
      },
    });
    await connect();
    expect((await client.listTools()).tools[0]?.outputSchema?.type).toBe("object");
    expect(await client.callTool({ name: "ping" })).toEqual({
      content: [{ type: "text", text: '{"status":"ok"}' }],
      structuredContent: { status: "ok" },
    });
  });

  test.each([
    null, [], {}, { count: "wrong" }, { count: 0 }, { count: 1, extra: true },
  ])("rejects invalid final output %j using the complete schema", async (value) => {
    app.tool("invalid", {
      output: z.object({ count: z.number() }).strict().refine(async ({ count }) => count > 0),
      // Deliberately simulate a malformed runtime result despite the static contract.
      handler: () => value as { count: number },
    });
    await connect();
    await client.listTools();
    const result = await client.callTool({ name: "invalid" });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toBeUndefined();
    expect(result.content).toEqual([{
      type: "text", text: expect.stringContaining("Output validation error"),
    }]);
  });

  test.each([
    { label: "extra fields", value: { count: 4, extra: true } },
    { label: "missing defaults", value: {} },
    { label: "extra fields and missing defaults", value: { extra: true } },
  ])("normalizes $label after output schema discovery", async ({ value }) => {
    app.tool("final", {
      output: z.object({ count: z.number().default(4) }),
      // Exercise runtime normalization despite the handler's static output contract.
      handler: () => value as { count: number },
    });
    await connect();
    expect((await client.listTools()).tools[0]?.outputSchema).toMatchObject({
      type: "object",
      required: ["count"],
      additionalProperties: false,
    });
    expect(await client.callTool({ name: "final" })).toEqual({
      content: [{ type: "text", text: '{"count":4}' }],
      structuredContent: { count: 4 },
    });
  });

  test("handler errors remain tool errors without structured content", async () => {
    app.tool("fails", {
      output: z.object({ ok: z.boolean() }),
      handler: () => { throw new Error("Expected handler failure"); },
    });
    await connect();
    await client.listTools();
    expect(await client.callTool({ name: "fails" })).toEqual({
      isError: true,
      content: [{ type: "text", text: "Expected handler failure" }],
    });
  });

  test.each([
    { label: "object", value: { ok: true } },
    { label: "array", value: [1, 2] },
    { label: "string", value: "hello" },
    { label: "null", value: null },
  ])("keeps undeclared $label outputs text-only", async ({ value }) => {
    app.tool("legacy", { handler: () => value });
    await connect();
    expect((await client.listTools()).tools[0]?.outputSchema).toBeUndefined();
    expect(await client.callTool({ name: "legacy" })).toEqual({
      content: [{ type: "text", text: JSON.stringify(value) }],
    });
  });

  test.each([
    { label: "scalar", output: z.string(), value: "hello" },
    { label: "array", output: z.array(z.number()), value: [1] },
    { label: "optional object", output: z.object({ n: z.number() }).optional(), value: { n: 1 } },
    { label: "object transform", output: z.string().transform(n => ({ n: Number(n) })), value: { n: 1 } },
    { label: "nested transform", output: z.object({ n: z.string().transform(Number) }), value: { n: 1 } },
    { label: "nested pipeline", output: z.object({ n: z.string().transform(Number).pipe(z.number()) }), value: { n: 1 } },
    { label: "preprocessor", output: z.object({ n: z.preprocess(Number, z.number()) }), value: { n: 1 } },
    { label: "unrepresentable field", output: z.object({ date: z.date() }), value: { date: new Date(0) } },
  ])("keeps unsupported $label schemas discoverable and text-only", async ({ output, value }) => {
    app.tool<unknown, unknown>("unsupported", { output, handler: () => value });
    await connect();
    expect((await client.listTools()).tools[0]?.outputSchema).toBeUndefined();
    expect(await client.callTool({ name: "unsupported" })).toEqual({
      content: [{ type: "text", text: JSON.stringify(value) }],
    });
  });
});

describe("McpApp.fetch", () => {
  let app: ReturnType<typeof mcp>;

  afterEach(async () => {
    await app?.stop();
  });

  test("fetch is a function on the app instance", () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });
    expect(typeof app.fetch).toBe("function");
  });

  test("fetch handles well-known health check", async () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });

    const req = new Request("http://localhost/.well-known/health-check");
    const res = await app.fetch(req);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("OK 200");
  });

  test("discovery includes developerEmail in the signed manifest", async () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });
    const res = await app.fetch(new Request("http://localhost/.well-known/futurity/plugin"));
    expect(res.status).toBe(200);
    const payload = await res.text();
    expect(JSON.parse(payload).developerEmail).toBe("developer@example.com");
    expect(verifyPayload(payload, res.headers.get("X-Futurity-Signature")!, signingKeys.publicKey)).toBe(true);
  });

  test("fetch handles MCP initialization", async () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });
    app.tool("hello", {
      description: "Say hello",
      handler: async () => ({ message: "hi" }),
    });

    const req = new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test-client", version: "1.0.0" },
        },
        id: 1,
      }),
    });

    const res = await app.fetch(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("mcp-session-id")).toBeString();
  });

  test("fetch returns 404 for unknown paths", async () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });

    const req = new Request("http://localhost/unknown");
    const res = await app.fetch(req);

    expect(res.status).toBe(404);
  });

  test("listen() still works as before", async () => {
    app = mcp({ name: "test", version: "1.0.0", pluginManifest });
    app.tool("ping", {
      description: "Ping",
      handler: async () => ({ pong: true }),
    });

    await app.listen(19876);

    const res = await fetch("http://localhost:19876/.well-known/health-check");
    expect(res.status).toBe(200);
  });
});
