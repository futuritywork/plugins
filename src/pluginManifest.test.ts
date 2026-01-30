import { test, expect, describe } from "bun:test";
import {
	PluginManifestSchema,
	PluginManifestSchemaCompat,
	PluginManifestSchemaV1,
	AuthForwardingSchema,
	ChainedAuthSchema,
} from "./pluginManifest";

// v2 manifest with forwarding auth (new format)
const validManifestV2Forwarding = {
	specVersion: 2,
	pluginId: "monday",
	name: "monday.com MCP Server",
	version: "1.0.0",
	auth: {
		type: "forwarding" as const,
		tokenEndpoint: "https://auth.monday.com/oauth2/token",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: [
			"me:read",
			"boards:read",
			"boards:write",
			"workspaces:read",
			"updates:read",
			"updates:write",
		],
		deliveryMethod: "header" as const,
	},
	mcpUrl: "https://mcp.example.com/mcp",
};

// v2 manifest with chained auth
const validManifestV2Chained = {
	specVersion: 2,
	pluginId: "monday-chained",
	name: "monday.com MCP Server (Chained)",
	version: "1.0.0",
	auth: {
		type: "chained" as const,
		authorizationEndpoint: "https://plugin.example.com/auth/authorize",
		callbackEndpoint: "https://plugin.example.com/auth/callback",
		tokenEndpoint: "https://plugin.example.com/auth/token",
		requiredUserContext: ["user_id", "organization_id"] as const,
		externalServices: [
			{
				name: "Monday.com",
				authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
				requiredScopes: ["me:read", "boards:read"],
			},
		],
		sessionConfig: {
			maxSessionDuration: 86400000,
			supportsRefresh: true,
		},
	},
	mcpUrl: "https://mcp.example.com/mcp",
};

// v1 manifest (legacy format with authForwarding)
const validManifestV1 = {
	specVersion: 1,
	pluginId: "monday",
	name: "monday.com MCP Server",
	version: "1.0.0",
	authForwarding: {
		tokenEndpoint: "https://auth.monday.com/oauth2/token",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: [
			"me:read",
			"boards:read",
			"boards:write",
			"workspaces:read",
			"updates:read",
			"updates:write",
		],
		deliveryMethod: "header" as const,
	},
	mcpUrl: "https://mcp.example.com/mcp",
};

describe("PluginManifestSchema v2", () => {
	test("accepts a valid v2 manifest with forwarding auth", () => {
		const result = PluginManifestSchema.parse(validManifestV2Forwarding);
		expect(result.pluginId).toBe("monday");
		expect(result.specVersion).toBe(2);
		expect(result.auth.type).toBe("forwarding");
		if (result.auth.type === "forwarding") {
			expect(result.auth.tokenEndpoint).toBe(
				"https://auth.monday.com/oauth2/token"
			);
		}
	});

	test("accepts a valid v2 manifest with chained auth", () => {
		const result = PluginManifestSchema.parse(validManifestV2Chained);
		expect(result.pluginId).toBe("monday-chained");
		expect(result.specVersion).toBe(2);
		expect(result.auth.type).toBe("chained");
		if (result.auth.type === "chained") {
			expect(result.auth.authorizationEndpoint).toBe(
				"https://plugin.example.com/auth/authorize"
			);
			expect(result.auth.callbackEndpoint).toBe(
				"https://plugin.example.com/auth/callback"
			);
			expect(result.auth.externalServices).toHaveLength(1);
			expect(result.auth.sessionConfig?.supportsRefresh).toBe(true);
		}
	});

	test("applies defaults for optional chained auth fields", () => {
		const minimal = {
			specVersion: 2,
			pluginId: "test",
			name: "Test Plugin",
			version: "1.0.0",
			auth: {
				type: "chained" as const,
				authorizationEndpoint: "https://plugin.example.com/auth/authorize",
				callbackEndpoint: "https://plugin.example.com/auth/callback",
			},
			mcpUrl: "https://mcp.example.com/mcp",
		};
		const result = PluginManifestSchema.parse(minimal);
		expect(result.auth.type).toBe("chained");
		if (result.auth.type === "chained") {
			expect(result.auth.requiredUserContext).toEqual(["user_id"]);
			expect(result.auth.externalServices).toBeUndefined();
			expect(result.auth.tokenEndpoint).toBeUndefined();
		}
	});

	test("rejects specVersion 0", () => {
		const invalid = { ...validManifestV2Forwarding, specVersion: 0 };
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects specVersion 3", () => {
		const invalid = { ...validManifestV2Forwarding, specVersion: 3 };
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects invalid auth type", () => {
		const invalid = {
			...validManifestV2Forwarding,
			auth: { ...validManifestV2Forwarding.auth, type: "oauth" },
		};
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects chained auth without required endpoints", () => {
		const invalid = {
			specVersion: 2,
			pluginId: "test",
			name: "Test Plugin",
			version: "1.0.0",
			auth: {
				type: "chained" as const,
				authorizationEndpoint: "https://plugin.example.com/auth/authorize",
				// missing callbackEndpoint
			},
			mcpUrl: "https://mcp.example.com/mcp",
		};
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});

	test("rejects invalid requiredUserContext values", () => {
		const invalid = {
			...validManifestV2Chained,
			auth: {
				...validManifestV2Chained.auth,
				requiredUserContext: ["user_id", "invalid_field"],
			},
		};
		expect(() => PluginManifestSchema.parse(invalid)).toThrow();
	});
});

describe("PluginManifestSchemaV1 (legacy)", () => {
	test("accepts a valid v1 manifest", () => {
		const result = PluginManifestSchemaV1.parse(validManifestV1);
		expect(result.pluginId).toBe("monday");
		expect(result.specVersion).toBe(1);
		expect(result.authForwarding.tokenEndpoint).toBe(
			"https://auth.monday.com/oauth2/token"
		);
	});

	test("rejects v1 manifest with specVersion 2", () => {
		const invalid = { ...validManifestV1, specVersion: 2 };
		expect(() => PluginManifestSchemaV1.parse(invalid)).toThrow();
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
		const result = PluginManifestSchemaV1.parse(minimal);
		expect(result.authForwarding.requiredScopes).toEqual([]);
		expect(result.authForwarding.deliveryMethod).toBe("header");
		expect(result.authForwarding.maxTokenTtl).toBeUndefined();
	});
});

describe("PluginManifestSchemaCompat (backward compatibility)", () => {
	test("accepts v2 manifest with forwarding auth", () => {
		const result = PluginManifestSchemaCompat.parse(validManifestV2Forwarding);
		expect(result.specVersion).toBe(2);
		expect(result.auth.type).toBe("forwarding");
	});

	test("accepts v2 manifest with chained auth", () => {
		const result = PluginManifestSchemaCompat.parse(validManifestV2Chained);
		expect(result.specVersion).toBe(2);
		expect(result.auth.type).toBe("chained");
	});

	test("accepts v1 manifest and transforms to v2 format", () => {
		const result = PluginManifestSchemaCompat.parse(validManifestV1);
		expect(result.specVersion).toBe(1);
		expect(result.auth.type).toBe("forwarding");
		if (result.auth.type === "forwarding") {
			expect(result.auth.tokenEndpoint).toBe(
				"https://auth.monday.com/oauth2/token"
			);
		}
	});

	test("rejects invalid version format", () => {
		const invalid = { ...validManifestV2Forwarding, version: "v1" };
		expect(() => PluginManifestSchemaCompat.parse(invalid)).toThrow();
	});

	test("rejects invalid mcpUrl", () => {
		const invalid = { ...validManifestV2Forwarding, mcpUrl: "not-a-url" };
		expect(() => PluginManifestSchemaCompat.parse(invalid)).toThrow();
	});

	test("rejects empty pluginId", () => {
		const invalid = { ...validManifestV2Forwarding, pluginId: "" };
		expect(() => PluginManifestSchemaCompat.parse(invalid)).toThrow();
	});

	test("rejects invalid deliveryMethod in forwarding auth", () => {
		const invalid = {
			...validManifestV2Forwarding,
			auth: {
				...validManifestV2Forwarding.auth,
				deliveryMethod: "cookie",
			},
		};
		expect(() => PluginManifestSchemaCompat.parse(invalid)).toThrow();
	});
});

describe("AuthForwardingSchema", () => {
	test("requires type field", () => {
		const valid = {
			type: "forwarding" as const,
			tokenEndpoint: "https://auth.example.com/token",
			authorizationEndpoint: "https://auth.example.com/authorize",
		};
		const result = AuthForwardingSchema.parse(valid);
		expect(result.type).toBe("forwarding");
	});
});

describe("ChainedAuthSchema", () => {
	test("validates complete chained auth config", () => {
		const valid = {
			type: "chained" as const,
			authorizationEndpoint: "https://plugin.example.com/auth/authorize",
			callbackEndpoint: "https://plugin.example.com/auth/callback",
			tokenEndpoint: "https://plugin.example.com/auth/token",
			requiredUserContext: ["user_id", "email"] as const,
			externalServices: [
				{
					name: "External API",
					authorizationEndpoint: "https://external.com/oauth/authorize",
					requiredScopes: ["read", "write"],
				},
			],
			sessionConfig: {
				maxSessionDuration: 3600000,
				supportsRefresh: true,
			},
		};
		const result = ChainedAuthSchema.parse(valid);
		expect(result.type).toBe("chained");
		expect(result.requiredUserContext).toEqual(["user_id", "email"]);
		expect(result.externalServices).toHaveLength(1);
		expect(result.sessionConfig?.supportsRefresh).toBe(true);
	});

	test("applies defaults", () => {
		const minimal = {
			type: "chained" as const,
			authorizationEndpoint: "https://plugin.example.com/auth/authorize",
			callbackEndpoint: "https://plugin.example.com/auth/callback",
		};
		const result = ChainedAuthSchema.parse(minimal);
		expect(result.requiredUserContext).toEqual(["user_id"]);
		expect(result.sessionConfig).toBeUndefined();
	});
});
