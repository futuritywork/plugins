import { test, expect, describe, afterEach } from "bun:test";
import { mcp } from "./app";

describe("McpApp.fetch", () => {
  let app: ReturnType<typeof mcp>;

  afterEach(async () => {
    await app?.stop();
  });

  test("fetch is a function on the app instance", () => {
    app = mcp({ name: "test", version: "1.0.0" });
    expect(typeof app.fetch).toBe("function");
  });

  test("fetch handles well-known health check", async () => {
    app = mcp({ name: "test", version: "1.0.0" });

    const req = new Request("http://localhost/.well-known/health-check");
    const res = await app.fetch(req);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("OK 200");
  });

  test("fetch handles MCP initialization", async () => {
    app = mcp({ name: "test", version: "1.0.0" });
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
    app = mcp({ name: "test", version: "1.0.0" });

    const req = new Request("http://localhost/unknown");
    const res = await app.fetch(req);

    expect(res.status).toBe(404);
  });

  test("listen() still works as before", async () => {
    app = mcp({ name: "test", version: "1.0.0" });
    app.tool("ping", {
      description: "Ping",
      handler: async () => ({ pong: true }),
    });

    await app.listen(19876);

    const res = await fetch("http://localhost:19876/.well-known/health-check");
    expect(res.status).toBe(200);
  });
});
