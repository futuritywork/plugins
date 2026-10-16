import { test, expect, describe } from "bun:test";
import {
	PluginManifestSchema,
	AuthForwardingSchema,
	ChainedAuthSchema,
	GovernanceSchema,
	type ChainedAuth,
	type Governance,
} from "./pluginManifest";

const validManifest = {
	specVersion: 3,
	pluginId: "monday",
	name: "monday.com MCP Server",
	version: "1.0.0",
	auth: {
		type: "forwarding" as const,
		tokenEndpoint: "https://auth.monday.com/oauth2/token",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: ["me:read", "boards:read", "boards:write"],
		deliveryMethod: "header" as const,
	},
	mcpUrl: "https://mcp.example.com/mcp",
};

const chainedAuth = {
	type: "chained" as const,
	authorizationEndpoint: "https://plugin.example.com/auth/authorize",
	callbackEndpoint: "https://plugin.example.com/auth/callback",
	tokenEndpoint: "https://plugin.example.com/auth/token",
	requiredUserContext: ["user_id", "organization_id"],
	externalServices: [{
		name: "Monday.com",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: ["me:read", "boards:read"],
	}],
	sessionConfig: { maxSessionDuration: 86400000, supportsRefresh: true },
} satisfies ChainedAuth;

const governance = {
	timezone: "America/New_York",
	purpose: "Manage projects and their owners",
	credential: "organization",
	defaultAccess: "restricted",
	restrictedByDefault: ["projects"],
	datasets: {
		people: {
			title: "People",
			fields: [{ name: "id", type: "string", identifier: "person", nullable: false }],
		},
		projects: {
			title: "Projects",
			description: "Active projects",
			group: "Work",
			paths: ["/projects"],
			fields: [
				{ name: "owner", type: "string", references: { dataset: "people", field: "id" }, nullable: true },
				{ name: "due", type: "datetime", clock: "wall" },
				{ name: "created", type: "datetime", clock: "instant" },
				{ name: "duration", type: "number", unit: "seconds" },
			],
			probe: { tool: "list_projects", args: { limit: 1, filter: { active: true } } },
		},
	},
} satisfies Governance;

describe("PluginManifestSchema v3", () => {
	test("accepts a v3 manifest", () => {
		const result = PluginManifestSchema.parse(validManifest);
		expect(result.specVersion).toBe(3);
		expect(result.pluginId).toBe("monday");
		expect(result.auth).toEqual({ ...validManifest.auth, grantType: "authorization_code" });
		expect(result.governance).toBeUndefined();
		expect(result.icon).toBeUndefined();
	});

	test("preserves complete chained auth config", () => {
		const result = PluginManifestSchema.parse({ ...validManifest, auth: chainedAuth });
		expect(result.auth).toEqual(chainedAuth);
	});

	test("applies defaults to minimal chained auth", () => {
		const auth = {
			type: "chained" as const,
			authorizationEndpoint: chainedAuth.authorizationEndpoint,
			callbackEndpoint: chainedAuth.callbackEndpoint,
		};
		const result = PluginManifestSchema.parse({ ...validManifest, auth });
		expect(result.auth).toEqual({ ...auth, requiredUserContext: ["user_id"] });
	});

	test.each([undefined, "header", "query"])("accepts no auth with deliveryMethod %s", (deliveryMethod) => {
		const auth = { type: "none" as const, ...(deliveryMethod && { deliveryMethod }) };
		const result = PluginManifestSchema.parse({ ...validManifest, auth });
		expect(result.auth).toEqual(auth);
	});

	test.each([0, 1, 2, 4, "3", undefined])("rejects specVersion %s", (specVersion) => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, specVersion }).success).toBe(false);
	});

	test("rejects legacy authForwarding manifests", () => {
		const { auth, ...manifest } = validManifest;
		const { type, ...authForwarding } = auth;
		for (const specVersion of [1, 2, 3]) {
			expect(PluginManifestSchema.safeParse({ ...manifest, specVersion, authForwarding }).success).toBe(false);
		}
	});

	test.each(["v1", "1.0", "1.0.0-beta", "1.0.0+build", ""])("rejects non-producer version %s", (version) => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, version }).success).toBe(false);
	});

	test.each([
		{ pluginId: "" },
		{ name: "" },
		{ mcpUrl: "not-a-url" },
		{ icon: 123 },
		{ auth: { ...validManifest.auth, type: "oauth" } },
		{ auth: { ...validManifest.auth, deliveryMethod: "cookie" } },
		{ auth: { type: "none", deliveryMethod: "cookie" } },
		{ auth: { ...chainedAuth, callbackEndpoint: undefined } },
		{ auth: { ...chainedAuth, requiredUserContext: ["invalid_field"] } },
	])("rejects invalid manifest fields %j", (invalid) => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, ...invalid }).success).toBe(false);
	});

	test("preserves governance and an optional icon string", () => {
		const result = PluginManifestSchema.parse({ ...validManifest, governance, icon: "📋" });
		expect(result.governance).toEqual(governance);
		expect(result.icon).toBe("📋");
	});

	test.each(["client_credentials", "urn:ietf:params:oauth:grant-type:saml2-bearer"])("accepts admin grant %s without redirect", (grantType) => {
		const result = PluginManifestSchema.parse({
			...validManifest,
			auth: { type: "forwarding", tokenEndpoint: validManifest.auth.tokenEndpoint, grantType },
		});
		expect(result.auth).toEqual({
			type: "forwarding", tokenEndpoint: validManifest.auth.tokenEndpoint,
			grantType, requiredScopes: [], deliveryMethod: "header",
		});
	});

	test.each([undefined, "authorization_code"])("requires authorizationEndpoint for grant %s", (grantType) => {
		const result = PluginManifestSchema.safeParse({
			...validManifest,
			auth: { type: "forwarding", tokenEndpoint: validManifest.auth.tokenEndpoint, grantType },
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues).toContainEqual(expect.objectContaining({
				path: ["auth", "authorizationEndpoint"],
				message: "authorizationEndpoint is required when grantType is authorization_code",
			}));
		}
	});

	test("rejects invalid grantType", () => {
		expect(PluginManifestSchema.safeParse({
			...validManifest, auth: { ...validManifest.auth, grantType: "password" },
		}).success).toBe(false);
	});
});

describe("GovernanceSchema", () => {
	test.each(["organization", "user"])("accepts credential %s and empty dataset collection", (credential) => {
		expect(GovernanceSchema.parse({ credential, datasets: {} })).toEqual({ credential, datasets: {} });
	});

	test("preserves omitted nullable as unknown", () => {
		const result = GovernanceSchema.parse(governance);
		expect(result.datasets.projects?.fields?.[1]?.nullable).toBeUndefined();
	});

	test.each(["", "project.items", "project items", "project\titems", "project\nitems"])("rejects dataset id %j", (id) => {
		expect(() => GovernanceSchema.parse({
			credential: "user", datasets: { [id]: governance.datasets.people },
		})).toThrow("Data set id");
	});

	test.each([{ fields: undefined }, { fields: [] }])("rejects fieldless datasets (%j)", ({ fields }) => {
		expect(() => GovernanceSchema.parse({
			credential: "user", datasets: { people: { title: "People", fields } },
		})).toThrow("declares no fields");
	});

	test.each([
		{ dataset: "missing", field: "id" },
		{ dataset: "people", field: "missing" },
	])("rejects undeclared reference %j", (references) => {
		expect(() => GovernanceSchema.parse({
			...governance,
			datasets: {
				...governance.datasets,
				projects: { title: "Projects", fields: [{ name: "owner", type: "string", references }] },
			},
		})).toThrow("a field references a data set or field that is not declared");
	});

	test("rejects restrictions on undeclared datasets", () => {
		expect(() => GovernanceSchema.parse({ ...governance, restrictedByDefault: ["missing"] }))
			.toThrow("restrictedByDefault names a data set that is not declared");
	});

	test("validates governance through the manifest boundary", () => {
		expect(() => PluginManifestSchema.parse({
			...validManifest, governance: { ...governance, restrictedByDefault: ["missing"] },
		})).toThrow("restrictedByDefault names a data set that is not declared");
	});

	test.each([
		{ credential: "team" }, { credential: undefined },
		{ timezone: "" }, { purpose: "" }, { defaultAccess: "private" },
	])("rejects invalid governance properties %j", (invalid) => {
		expect(GovernanceSchema.safeParse({ ...governance, ...invalid }).success).toBe(false);
	});

	test.each([
		{ title: "" }, { paths: [""] }, { probe: { tool: "", args: {} } },
		{ probe: { tool: "list_people", args: [] } },
	])("rejects invalid dataset properties %j", (invalid) => {
		expect(GovernanceSchema.safeParse({
			credential: "user", datasets: { people: { ...governance.datasets.people, ...invalid } },
		}).success).toBe(false);
	});

	test.each([
		{ name: "" }, { type: "" }, { identifier: "" }, { unit: "" },
		{ nullable: "unknown" }, { clock: "local" },
		{ references: { dataset: "", field: "id" } },
		{ references: { dataset: "people", field: "" } },
	])("rejects invalid field properties %j", (invalid) => {
		expect(GovernanceSchema.safeParse({
			credential: "user",
			datasets: { people: { title: "People", fields: [{ name: "id", type: "string", ...invalid }] } },
		}).success).toBe(false);
	});
});

describe("AuthForwardingSchema", () => {
	test("applies defaults", () => {
		const result = AuthForwardingSchema.parse({
			type: "forwarding", tokenEndpoint: validManifest.auth.tokenEndpoint,
		});
		expect(result.grantType).toBe("authorization_code");
		expect(result.requiredScopes).toEqual([]);
		expect(result.deliveryMethod).toBe("header");
		expect(result.maxTokenTtl).toBeUndefined();
	});

	test("requires the forwarding type", () => {
		expect(AuthForwardingSchema.safeParse({ tokenEndpoint: validManifest.auth.tokenEndpoint }).success).toBe(false);
	});

	test.each(["client_credentials", "urn:ietf:params:oauth:grant-type:saml2-bearer"])("accepts %s without authorizationEndpoint", (grantType) => {
		const result = AuthForwardingSchema.parse({
			type: "forwarding", tokenEndpoint: validManifest.auth.tokenEndpoint, grantType,
		});
		expect(result.grantType).toBe(grantType);
		expect(result.authorizationEndpoint).toBeUndefined();
	});
});

describe("ChainedAuthSchema", () => {
	test("preserves complete config", () => {
		expect(ChainedAuthSchema.parse(chainedAuth)).toEqual(chainedAuth);
	});

	test("applies defaults", () => {
		const result = ChainedAuthSchema.parse({
			type: "chained",
			authorizationEndpoint: chainedAuth.authorizationEndpoint,
			callbackEndpoint: chainedAuth.callbackEndpoint,
			externalServices: [{ name: "External API", authorizationEndpoint: chainedAuth.authorizationEndpoint }],
			sessionConfig: {},
		});
		expect(result.requiredUserContext).toEqual(["user_id"]);
		expect(result.tokenEndpoint).toBeUndefined();
		expect(result.externalServices?.[0]?.requiredScopes).toEqual([]);
		expect(result.sessionConfig?.supportsRefresh).toBe(false);
	});

	test("keeps optional session and external services absent", () => {
		const result = ChainedAuthSchema.parse({
			type: "chained",
			authorizationEndpoint: chainedAuth.authorizationEndpoint,
			callbackEndpoint: chainedAuth.callbackEndpoint,
		});
		expect(result.requiredUserContext).toEqual(["user_id"]);
		expect(result.sessionConfig).toBeUndefined();
		expect(result.externalServices).toBeUndefined();
	});
});
