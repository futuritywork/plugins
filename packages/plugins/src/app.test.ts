import { test, expect, describe, afterEach, beforeEach } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { FUTURITY_META_KEY, type PluginManifestInput } from "@futurity/plugin-manifest";
import { mcp, setOutputViolationHandler, type OutputViolationReport } from "./app";

const manifest: PluginManifestInput = {
  name: "work.futurity/test",
  title: "Test",
  description: "A plugin under test",
  version: "1.2.3",
  websiteUrl: "https://example.com",
  remotes: [{ type: "streamable-http", url: "http://localhost/mcp" }],
  _meta: {
    [FUTURITY_META_KEY]: {
      specVersion: 5,
      developer: { email: "developer@example.com" },
      credentials: [{ id: "public", label: "Public", holder: "none", method: { type: "none" }, fields: [] }],
    },
  },
};

describe("McpApp tool outputs", () => {
  let app: ReturnType<typeof mcp>;
  let client: Client;
  let reports: OutputViolationReport[];

  beforeEach(() => {
    app = mcp({ manifest, futurity: false });
    client = new Client({ name: "test-client", version: "1.0.0" });
    reports = [];
    setOutputViolationHandler((report) => { reports.push(report); });
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

  /** The answer as it crosses the wire, unchecked against the advertised schema, as Futurity reads it. */
  async function callRaw(name: string, args: Record<string, unknown> = {}) {
    return await client.request({ method: "tools/call", params: { name, arguments: args } }, CallToolResultSchema);
  }

  test("advertises object outputs and returns structured content alongside JSON text", async () => {
    app.tool("add", {
      input: z.object({ a: z.number(), b: z.number() }),
      output: z.object({ sum: z.number().describe("The sum") }),
      annotations: { title: "Add", readOnlyHint: true, idempotentHint: true },
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
    expect(tools[0]?.annotations).toEqual({ title: "Add", readOnlyHint: true, idempotentHint: true });
    expect(tools[0]?._meta).toBeUndefined();
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

  test("a connection's tool list carries the input schema listedInput gives it, and calls still parse with input", async () => {
    app.tool("pick", {
      input: z.object({ id: z.number().int() }),
      output: z.object({ id: z.number() }),
      listedInput: (schema, { signal }) => {
        expect(signal).toBeInstanceOf(AbortSignal);
        const properties = { id: { type: "integer", oneOf: [{ const: 7, title: "Seven" }] } };
        return { ...schema, properties };
      },
      handler: ({ id }) => ({ id }),
    });
    await connect();

    const { tools } = await client.listTools();
    const called = await client.callTool({ name: "pick", arguments: { id: 8 } });

    expect(tools[0]?.inputSchema.properties).toEqual({ id: { type: "integer", oneOf: [{ const: 7, title: "Seven" }] } });
    expect(called.content).toEqual([{ type: "text", text: '{"id":8}' }]);
  });

  test("supports output schemas on tools without an input schema", async () => {
    app.tool("ping", {
      output: z.object({ status: z.literal("ok") }),
      handler: (input, { signal }) => {
        expect(input).toEqual({});
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

  test.each<[unknown]>([
    [null], [[]], [{}], [{ count: "wrong" }], [{ count: 0 }], [{ count: 1, extra: true }],
  ])("a result %j that misses the complete schema still answers the call and is reported", async (value) => {
    app.tool("invalid", {
      output: z.object({ count: z.number() }).strict().refine(async ({ count }) => count > 0),
      // Deliberately simulate a malformed runtime result despite the static contract.
      handler: () => value as { count: number },
    });
    await connect();

    const result = await callRaw("invalid");

    const isObject = typeof value === "object" && value !== null && !Array.isArray(value);
    expect(result.isError).toBeUndefined();
    expect(result.content).toEqual([{ type: "text", text: JSON.stringify(value) }]);
    expect(result.structuredContent).toEqual(isObject ? (value as Record<string, unknown>) : undefined);
    expect(reports).toEqual([{
      caller: "invalid",
      schema: "work.futurity/test output",
      issues: expect.any(String),
      timestamp: expect.any(String),
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

  test("an output schema AJV cannot compile cannot be registered", () => {
    const register = () => app.tool("invalid-pattern", {
      output: z.object({ value: z.string().regex(/a\-/) }),
      handler: () => ({ value: "a-" }),
    });

    expect(register).toThrow("Tool invalid-pattern output cannot be advertised");
  });

  test("a result Zod accepts but the advertised JSON Schema refuses still answers the call and is reported", async () => {
    app.tool("case-insensitive", {
      input: z.object({ value: z.string() }),
      output: z.object({ value: z.string().regex(/^abc$/i) }),
      handler: ({ value }) => ({ value }),
    });
    await connect();
    await client.listTools();

    const mismatched = await callRaw("case-insensitive", { value: "ABC" });
    const matching = await client.callTool({ name: "case-insensitive", arguments: { value: "abc" } });

    expect(mismatched).toEqual({
      content: [{ type: "text", text: '{"value":"ABC"}' }],
      structuredContent: { value: "ABC" },
    });
    expect(matching).toEqual({
      content: [{ type: "text", text: '{"value":"abc"}' }],
      structuredContent: { value: "abc" },
    });
    expect(reports).toHaveLength(1);
    expect(reports[0]?.issues).toStartWith("JSON Schema:");
  });

  test("a report names what the result missed and carries no value from it", async () => {
    app.tool("leaky", {
      output: z.object({ count: z.number(), notes: z.array(z.string()) }),
      handler: () => ({ count: "sentinel-count", notes: ["sentinel-note", 7], hidden: "sentinel-field" }) as unknown as { count: number; notes: string[] },
    });
    await connect();

    await callRaw("leaky");

    expect(reports).toHaveLength(1);
    expect(reports[0]?.issues).toContain("count:");
    expect(JSON.stringify(reports[0])).not.toContain("sentinel");
  });

  test("a reporter that throws leaves the call answered", async () => {
    setOutputViolationHandler(() => { throw new Error("reporter down"); });
    app.tool("off-contract", {
      output: z.object({ count: z.number() }),
      handler: () => ({ count: "many" }) as unknown as { count: number },
    });
    await connect();

    expect(await callRaw("off-contract")).toEqual({
      content: [{ type: "text", text: '{"count":"many"}' }],
      structuredContent: { count: "many" },
    });
  });

  test("local datetimes accepted by both validators retain structured output", async () => {
    app.tool("local-time", {
      output: z.object({ at: z.iso.datetime({ local: true }) }),
      handler: () => ({ at: "2026-01-01T12:00:00" }),
    });
    await connect();
    expect((await client.listTools()).tools[0]?.outputSchema?.type).toBe("object");
    expect(await client.callTool({ name: "local-time" })).toEqual({
      content: [{ type: "text", text: '{"at":"2026-01-01T12:00:00"}' }],
      structuredContent: { at: "2026-01-01T12:00:00" },
    });
  });

  test.each([false, true])("an overwrite schema cannot be registered and never runs its rewrite (root: %s)", (root) => {
    let rewrites = 0;
    const rewrite = (n: number) => { rewrites++; return n + 1; };
    const output = root
      ? z.object({ n: z.number().max(2) }).overwrite(({ n }) => ({ n: rewrite(n) }))
      : z.object({ n: z.number().overwrite(rewrite).max(2) });

    expect(() => app.tool("overwrite", { output, handler: () => ({ n: 1 }) })).toThrow("Tool overwrite output cannot be advertised");
    expect(rewrites).toBe(0);
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

  test("a tool without an output schema does not compile and cannot be registered", () => {
    // @ts-expect-error output is required
    const register = () => app.tool("undeclared", { handler: () => ({ ok: true }) });

    expect(register).toThrow("Tool undeclared must declare an output schema");
  });

  test.each([
    { label: "scalar", output: z.string() },
    { label: "array", output: z.array(z.number()) },
    { label: "unknown", output: z.unknown() },
    { label: "optional object", output: z.object({ n: z.number() }).optional() },
    { label: "nullable object", output: z.object({ n: z.number() }).nullable() },
    { label: "object transform", output: z.string().transform(n => ({ n: Number(n) })) },
    { label: "union with a scalar branch", output: z.union([z.object({ n: z.number() }), z.string()]) },
  ])("an output that is not an object cannot be registered: $label", ({ output }) => {
    const register = () => app.tool<unknown, unknown>("unsupported", { output, handler: () => ({}) });

    expect(register).toThrow("Tool unsupported output must be an object schema or a union of objects");
  });

  test.each([
    { label: "nested transform", output: z.object({ n: z.string().transform(Number) }) },
    { label: "nested pipeline", output: z.object({ n: z.string().transform(Number).pipe(z.number()) }) },
    { label: "preprocessor", output: z.object({ n: z.preprocess(Number, z.number()) }) },
    { label: "unrepresentable field", output: z.object({ date: z.date() }) },
    { label: "transform inside a union branch", output: z.union([z.object({ n: z.string().transform(Number) }), z.object({ error: z.string() })]) },
  ])("an output the client could not check cannot be registered: $label", ({ output }) => {
    const register = () => app.tool<unknown, unknown>("unsupported", { output, handler: () => ({}) });

    expect(register).toThrow("Tool unsupported output cannot be advertised");
  });

  test("a union output is advertised as an object constrained by each branch and each branch reaches the client structured", async () => {
    app.tool("lookup", {
      input: z.object({ id: z.number() }),
      output: z.union([z.object({ name: z.string() }), z.object({ error: z.string() })]),
      handler: ({ id }) => (id === 1 ? { name: "one" } : { error: "not found" }),
    });
    await connect();

    const { tools } = await client.listTools();
    const found = await client.callTool({ name: "lookup", arguments: { id: 1 } });
    const missing = await client.callTool({ name: "lookup", arguments: { id: 2 } });

    expect(tools[0]?.outputSchema?.type).toBe("object");
    expect(tools[0]?.outputSchema?.anyOf).toHaveLength(2);
    expect(found.structuredContent).toEqual({ name: "one" });
    expect(missing.structuredContent).toEqual({ error: "not found" });
  });

  test("a result that matches no union branch still answers the call and is reported", async () => {
    app.tool("lookup", {
      output: z.union([z.object({ name: z.string() }), z.object({ error: z.string() })]),
      handler: () => ({ other: true }) as unknown as { name: string },
    });
    await connect();

    const result = await callRaw("lookup");

    expect(result).toEqual({
      content: [{ type: "text", text: '{"other":true}' }],
      structuredContent: { other: true },
    });
    expect(reports.map((report) => report.caller)).toEqual(["lookup"]);
  });
});

describe("McpApp tool inputs", () => {
  let app: ReturnType<typeof mcp>;
  let client: Client;

  beforeEach(() => {
    app = mcp({ manifest, futurity: false });
    client = new Client({ name: "test-client", version: "1.0.0" });
  });

  afterEach(async () => {
    await client.close();
    await app.stop();
  });

  async function connect() {
    await client.connect(new StreamableHTTPClientTransport(new URL("http://localhost/mcp"), {
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));
  }

  function text(result: Awaited<ReturnType<Client["callTool"]>>): string {
    return (result.content as { text: string }[])[0]!.text;
  }

  test("a strict input refuses unknown keys and advertises that it does", async () => {
    app.tool("lookup", {
      input: z.strictObject({ id: z.string() }),
      output: z.object({ id: z.string() }),
      handler: ({ id }) => ({ id }),
    });
    await connect();

    const { tools } = await client.listTools();
    const refused = await client.callTool({ name: "lookup", arguments: { id: "a", stray: true } });
    const accepted = await client.callTool({ name: "lookup", arguments: { id: "a" } });

    expect(tools[0]?.inputSchema).toMatchObject({ type: "object", required: ["id"], additionalProperties: false });
    expect(refused.isError).toBe(true);
    expect(text(refused)).toContain("Input validation error");
    expect(text(accepted)).toBe('{"id":"a"}');
  });

  test("a refinement on the input object rejects arguments that break it", async () => {
    app.tool("range", {
      input: z.object({ from: z.number(), to: z.number() }).refine(({ from, to }) => from <= to, "from must not exceed to"),
      output: z.object({ span: z.number() }),
      handler: ({ from, to }) => ({ span: to - from }),
    });
    await connect();

    const refused = await client.callTool({ name: "range", arguments: { from: 5, to: 1 } });
    const accepted = await client.callTool({ name: "range", arguments: { from: 1, to: 5 } });

    expect(refused.isError).toBe(true);
    expect(text(refused)).toContain("from must not exceed to");
    expect(text(accepted)).toBe('{"span":4}');
  });

  test("a union input is advertised as an object constrained by each branch and parsed as the union", async () => {
    app.tool("find", {
      input: z.union([z.strictObject({ by: z.literal("id"), id: z.string() }), z.strictObject({ by: z.literal("email"), email: z.email() })]),
      output: z.looseObject({ by: z.string() }),
      handler: (input) => input,
    });
    await connect();

    const { tools } = await client.listTools();
    const byEmail = await client.callTool({ name: "find", arguments: { by: "email", email: "a@example.com" } });
    const mixed = await client.callTool({ name: "find", arguments: { by: "id", email: "a@example.com" } });

    expect(tools[0]?.inputSchema.type).toBe("object");
    expect(tools[0]?.inputSchema.anyOf).toHaveLength(2);
    expect(text(byEmail)).toBe('{"by":"email","email":"a@example.com"}');
    expect(mixed.isError).toBe(true);
  });

  test("a tool whose input is not an object cannot be registered", () => {
    const register = () => app.tool("bad", { input: z.string(), output: z.object({}), handler: () => ({}) });

    expect(register).toThrow("Tool bad input must be an object schema, not string");
  });
});

describe("McpApp output fields that may be absent", () => {
  let app: ReturnType<typeof mcp>;
  let client: Client;

  afterEach(async () => {
    await client.close();
    await app.stop();
  });

  test("a result missing an unknown, any or optional field keeps its structured content", async () => {
    app = mcp({ manifest, futurity: false });
    client = new Client({ name: "test-client", version: "1.0.0" });
    app.tool("row", {
      output: z.object({
        id: z.string(),
        raw: z.unknown(),
        extra: z.any(),
        note: z.string().optional(),
        nested: z.object({ status: z.unknown(), code: z.number() }),
      }),
      handler: () => ({ id: "r1", raw: undefined, extra: undefined, nested: { status: undefined, code: 7 } }),
    });
    await client.connect(new StreamableHTTPClientTransport(new URL("http://localhost/mcp"), {
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));

    const { tools } = await client.listTools();
    const result = await client.callTool({ name: "row" });

    expect(tools[0]?.outputSchema?.required).toEqual(["id", "nested"]);
    expect(result).toEqual({
      content: [{ type: "text", text: '{"id":"r1","nested":{"code":7}}' }],
      structuredContent: { id: "r1", nested: { code: 7 } },
    });
  });
});

describe("McpApp.fetch", () => {
  let app: ReturnType<typeof mcp>;

  afterEach(async () => {
    await app?.stop();
  });

  test("fetch is a function on the app instance", () => {
    app = mcp({ manifest, futurity: false });
    expect(typeof app.fetch).toBe("function");
  });

  test("fetch handles well-known health check", async () => {
    app = mcp({ manifest, futurity: false });

    const req = new Request("http://localhost/.well-known/health-check");
    const res = await app.fetch(req);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("OK 200");
  });

  test("discovery serves the validated manifest as plain JSON with no signature", async () => {
    app = mcp({ manifest, futurity: false });

    const res = await app.fetch(new Request("http://localhost/.well-known/futurity/plugin"));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toStartWith("application/json");
    expect(res.headers.get("x-futurity-signature")).toBeNull();
    expect(await res.json()).toEqual(manifest);
  });

  test("a manifest that breaks a spec rule stops the app from being built", () => {
    const broken = { ...manifest, version: "1.0" };

    const build = () => mcp({ manifest: broken, futurity: false });

    expect(build).toThrow("version: must be semver x.y.z");
  });

  test("a client sees the manifest identity as server info and the instructions on initialize", async () => {
    app = mcp({ manifest, instructions: "Use for tests.", futurity: false });
    const client = new Client({ name: "test-client", version: "1.0.0" });

    await client.connect(new StreamableHTTPClientTransport(new URL("http://localhost/mcp"), {
      fetch: (url, init) => app.fetch(new Request(url.toString(), init)),
    }));

    expect(client.getServerVersion()).toEqual({
      name: "work.futurity/test",
      title: "Test",
      description: "A plugin under test",
      version: "1.2.3",
      websiteUrl: "https://example.com",
    });
    expect(client.getInstructions()).toBe("Use for tests.");
    await client.close();
  });

  test("fetch handles MCP initialization", async () => {
    app = mcp({ manifest, futurity: false });
    app.tool("hello", {
      description: "Say hello",
      output: z.object({ message: z.string() }),
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
    app = mcp({ manifest, futurity: false });

    const req = new Request("http://localhost/unknown");
    const res = await app.fetch(req);

    expect(res.status).toBe(404);
  });

  test("listen() still works as before", async () => {
    app = mcp({ manifest, futurity: false });
    app.tool("ping", {
      description: "Ping",
      output: z.object({ pong: z.boolean() }),
      handler: async () => ({ pong: true }),
    });

    await app.listen(19876);

    const res = await fetch("http://localhost:19876/.well-known/health-check");
    expect(res.status).toBe(200);
  });
});
