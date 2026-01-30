import { test, expect, describe } from "bun:test";
import { PluginManifestSchema } from "./pluginManifest";

const validManifest = {
	specVersion: 1,
	pluginId: "monday",
	name: "monday.com MCP Server",
	version: "1.0.0",
	authForwarding: {
		tokenEndpoint: "https://auth.monday.com/oauth2/token",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: ["me:read", "boards:read", "boards:write", "workspaces:read", "updates:read", "updates:write"],
		deliveryMethod: "header" as const,
	},
	mcpUrl: "https://mcp.example.com/mcp",
};

describe("PluginManifestSchema", () => {
	test("accepts a valid manifest", () => {
		const result = PluginManifestSchema.parse(validManifest);
		expect(result.pluginId).toBe("monday");
		expect(result.name).toBe("monday.com MCP Server");
		expect(result.version).toBe("1.0.0");
		expect(result.authForwarding.tokenEndpoint).toBe(
			"https://auth.monday.com/oauth2/token",
		);
		expect(result.mcpUrl).toBe("https://mcp.example.com/mcp");
	});

	test("applies defaults for optional authForwarding fields", () => {
		const minimal = {
			specVersion: 1,
			pluginId: "test",
			name: "Test Plugin",
			version: "1.0.0",
			mcpUrl: "https://mcp.example.com/mcp",
			authForwarding: {
				tokenEndpoint: "https://auth.example.com/token",
				authorizationEndpoint: "https://auth.example.com/authorize",
			},
		};
		const result = PluginManifestSchema.parse(minimal);
		expect(result.authForwarding.requiredScopes).toEqual([]);
		expect(result.authForwarding.deliveryMethod).toBe("header");
		expect(result.authForwarding.maxTokenTtl).toBeUndefined();
	});

	test("rejects invalid version format", () => {
		const invalid = { ...validManifest, version: "v1" };
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects invalid mcpUrl", () => {
		const invalid = { ...validManifest, mcpUrl: "not-a-url" };
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects empty pluginId", () => {
		const invalid = { ...validManifest, pluginId: "" };
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects invalid deliveryMethod", () => {
		const invalid = {
			...validManifest,
			authForwarding: {
				...validManifest.authForwarding,
				deliveryMethod: "cookie",
			},
		};
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});
});
