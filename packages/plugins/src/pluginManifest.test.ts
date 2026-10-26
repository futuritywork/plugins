import { test, expect, describe } from "bun:test";
import {
	PluginManifestSchema,
	AuthForwardingSchema,
	ChainedAuthSchema,
	GovernanceSchema,
	type ChainedAuth,
	type Governance,
	type PluginManifest,
} from "./pluginManifest";

const validManifest = {
	specVersion: 4,
	pluginId: "monday",
	developerEmail: "developer@example.com",
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

describe("PluginManifestSchema v4", () => {
	test("accepts a v4 manifest", () => {
		const result = PluginManifestSchema.parse(validManifest);
		expect(result.specVersion).toBe(4);
		expect(result.pluginId).toBe("monday");
		expect(result.developerEmail).toBe("developer@example.com");
		expect(result.auth).toEqual({ ...validManifest.auth, grantType: "authorization_code" });
		expect(result.governance).toBeUndefined();
		expect(result.icon).toBeUndefined();
	});

	test.each([undefined, null, "", "not-an-email", "https://example.com", 42])("rejects invalid developerEmail %j", (developerEmail) => {
		const result = PluginManifestSchema.safeParse({ ...validManifest, developerEmail });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues).toContainEqual(expect.objectContaining({ path: ["developerEmail"] }));
		}
	});

	test("rejects chained auth for custom registration", () => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, auth: chainedAuth }).success).toBe(false);
	});

	test.each([undefined, "header", "query"])("accepts no auth with deliveryMethod %s", (deliveryMethod) => {
		const auth = { type: "none" as const, ...(deliveryMethod && { deliveryMethod }) };
		const result = PluginManifestSchema.parse({ ...validManifest, auth });
		expect(result.auth).toEqual(auth);
	});

	test.each([0, 1, 2, 3, "4", undefined])("rejects specVersion %s", (specVersion) => {
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
		const result = PluginManifestSchema.parse({ ...validManifest, governance, icon: "https://example.com/icon.png" });
		expect(result.governance).toEqual(governance);
		expect(result.icon).toBe("https://example.com/icon.png");
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
		const result = GovernanceSchema.safeParse({
			credential: "user", datasets: { people: { title: "People", fields } },
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues).toContainEqual(expect.objectContaining({
				path: ["datasets", "people", "fields"],
				code: fields === undefined ? "invalid_type" : "too_small",
			}));
		}
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

	test.each(["missing", "constructor", "toString", "__proto__"])("rejects restrictions on undeclared dataset %s", (id) => {
		expect(() => GovernanceSchema.parse({ ...governance, datasets: {}, restrictedByDefault: [id] }))
			.toThrow("restrictedByDefault names a data set that is not declared");
	});

	test.each(["constructor", "toString"])("accepts restrictions on explicitly declared dataset %s", (id) => {
		const input: Governance = {
			credential: "user",
			datasets: { [id]: governance.datasets.people },
			restrictedByDefault: [id],
		};
		expect(GovernanceSchema.parse(input)).toEqual(input);
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

const credential = { key: "secret", label: "Secret", type: "password" as const };
const keypair = { key: "private_key_pem", label: "Certificate", type: "x509-keypair" as const, secondaryKey: "public_cert_pem" };

/** Exercises credential rules at the complete manifest boundary. */
function parseCredentials(credentials_schema: unknown, grantType = "credentials") {
	const auth = ["none", "credentials", "api_key"].includes(grantType)
		? { type: "none", grantType, credentials_schema }
		: { ...validManifest.auth, grantType, credentials_schema };
	return PluginManifestSchema.safeParse({ ...validManifest, auth });
}

describe("manifest credentials", () => {
	test("preserves credential display options and keypair keys", () => {
		const fields = [{ ...credential, required: true, placeholder: "Enter secret", help: "From your console" }, keypair];
		const result = parseCredentials(fields);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.auth.credentials_schema).toEqual(fields);
	});

	test.each([
		{ ...keypair, secondaryKey: undefined }, { ...keypair, secondaryKey: "" },
		{ ...credential, secondaryKey: "other" }, { ...credential, secondaryKey: "" },
	])("rejects invalid secondaryKey %j", (field) => {
		const result = parseCredentials([field]);
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error.issues).toContainEqual(expect.objectContaining({
			path: ["auth", "credentials_schema", 0, "secondaryKey"],
			message: "secondaryKey is required only for x509-keypair fields",
		}));
	});

	test.each([
		[credential, credential],
		[keypair, { ...credential, key: keypair.secondaryKey }],
		[{ ...credential, key: keypair.secondaryKey }, keypair],
		[keypair, { ...keypair, key: "other" }],
		[{ ...keypair, secondaryKey: keypair.key }],
	].map((fields) => ({ fields })))("rejects duplicate primary/secondary keys %j", ({ fields }) => {
		const result = parseCredentials(fields);
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error.issues).toContainEqual(expect.objectContaining({ message: "Credential keys must be unique" }));
	});

	test.each([".*", "", null, 42])("rejects unsupported pattern %j", (pattern) => {
		expect(parseCredentials([{ ...credential, pattern }]).success).toBe(false);
	});

	test.each([undefined, null, []].map((fields) => ({ fields })))("none accepts no fields, credentials requires fields: %j", ({ fields }) => {
		expect(parseCredentials(fields, "none").success).toBe(true);
		expect(parseCredentials(fields, "credentials").success).toBe(false);
	});

	test("none (including omitted grant) cannot collect fields", () => {
		expect(parseCredentials([credential], "none").success).toBe(false);
		expect(PluginManifestSchema.safeParse({ ...validManifest, auth: { type: "none", credentials_schema: [credential] } }).success).toBe(false);
	});

	const grants = [
		{ grant: "api_key", keys: ["api_key"] },
		{ grant: "client_credentials", keys: ["api_base_url", "client_id", "client_secret"] },
		{ grant: "urn:ietf:params:oauth:grant-type:saml2-bearer", keys: ["api_base_url", "client_id", "saml_subject_name_id", "private_key_pem", "public_cert_pem"] },
	];
	for (const { grant, keys } of grants) {
		test(`${grant} requires every key in explicit arrays`, () => {
			const fields = keys.map((key) => ({ ...credential, key }));
			expect(parseCredentials(fields, grant).success).toBe(true);
			expect(parseCredentials([], grant).success).toBe(false);
			for (const key of keys) {
				const result = parseCredentials(fields.filter((field) => field.key !== key), grant);
				expect(result.success).toBe(false);
				if (!result.success) expect(result.error.issues).toContainEqual(expect.objectContaining({
					path: ["auth", "credentials_schema"], message: `auth.credentials_schema must collect ${key} for ${grant}`,
				}));
			}
		});
		test.each([undefined, null])(`${grant} preserves platform-default fields %j`, (fields) => {
			const result = parseCredentials(fields, grant);
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.auth.credentials_schema).toBe(fields);
		});
	}

	test("SAML counts the secondary certificate key", () => {
		expect(parseCredentials([
			...['api_base_url', 'client_id', 'saml_subject_name_id'].map((key) => ({ ...credential, key })), keypair,
		], "urn:ietf:params:oauth:grant-type:saml2-bearer").success).toBe(true);
	});

	test.each([undefined, null, []].map((fields) => ({ fields })))("authorization_code accepts no fields: %j", ({ fields }) => {
		expect(parseCredentials(fields, "authorization_code").success).toBe(true);
	});

	test.each(["authorization_code", undefined])("OAuth rejects credential fields with grant %j", (grantType) => {
		const result = PluginManifestSchema.safeParse({
			...validManifest,
			auth: { ...validManifest.auth, grantType, credentials_schema: [credential] },
		});
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error.issues).toContainEqual(expect.objectContaining({
			path: ["auth", "credentials_schema"],
		}));
	});

	for (const key of ["grant_type", "data_api_params", "token_request_params"]) {
		test.each(["key", "secondaryKey"] as const)(`rejects reserved ${key} in %s`, (property) => {
			const field = property === "key" ? { ...credential, key } : { ...keypair, secondaryKey: key };
			const result = parseCredentials([field]);
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error.issues).toContainEqual(expect.objectContaining({
				path: ["auth", "credentials_schema", 0],
				message: `Credential key ${key} is reserved`,
			}));
		});
	}
});

describe("manifest URLs and metadata", () => {
	test.each(["/", "/oauth/token", "/oauth/token?tenant=demo"])("relative token endpoint %s requires an admin grant", (tokenEndpoint) => {
		for (const grantType of ["client_credentials", "urn:ietf:params:oauth:grant-type:saml2-bearer"]) {
			expect(PluginManifestSchema.safeParse({ ...validManifest, auth: { type: "forwarding", grantType, tokenEndpoint } }).success).toBe(true);
		}
		expect(PluginManifestSchema.safeParse({ ...validManifest, auth: { ...validManifest.auth, tokenEndpoint } }).success).toBe(false);
	});

	test.each(["//evil.example/token", "/\\evil.example", "/token#fragment", "/has space", "token", "ftp://example.com/token", "javascript:alert(1)", "file:///token"])("rejects token endpoint %j", (tokenEndpoint) => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, auth: { type: "forwarding", grantType: "client_credentials", tokenEndpoint } }).success).toBe(false);
	});

	const metadata = {
		tagline: "Connect work", overview: "Manage projects", setupType: "admin",
		oauth: { token_body: "json", setup_steps: ["Create credentials"], console_url: "https://example.com/console" },
		features: [{ title: "Read", description: "Read projects", category: "read_write", icon: "folder" }],
		permissions: ["read", { scope: "write", label: "Write", description: "Change projects", access: "admin", docsUrl: null }],
		links: { docs: "https://example.com/docs", privacy: "http://example.com/privacy" },
	} satisfies NonNullable<PluginManifest["metadata"]>;
	test.each([undefined, null, metadata])("preserves supported metadata %j", (metadata) => {
		expect(PluginManifestSchema.parse({ ...validManifest, metadata }).metadata).toEqual(metadata);
	});
	test.each([
		{ setupType: "owner" }, { oauth: { token_body: "xml" } }, { oauth: { setup_steps: [42] } },
		{ oauth: { console_url: "ftp://example.com" } }, { links: { docs: "/docs" } },
		{ links: { privacy: "javascript:alert(1)" } },
		{ features: [{ ...metadata.features[0], category: "admin" }] },
		{ permissions: [{ scope: "read", label: "Read", description: "Read", access: "owner", docsUrl: null }] },
		{ permissions: [{ scope: "read", label: "Read", description: "Read", access: "read", docsUrl: "file:///docs" }] },
	])("rejects invalid metadata %j", (invalid) => {
		expect(PluginManifestSchema.safeParse({ ...validManifest, metadata: { ...metadata, ...invalid } }).success).toBe(false);
	});
	test.each(["ftp://example.com", "javascript:alert(1)"])("rejects non-HTTP display and authorization URLs %s", (url) => {
		for (const overrides of [{ mcpUrl: url }, { icon: url }, { auth: { ...validManifest.auth, authorizationEndpoint: url } }]) {
			expect(PluginManifestSchema.safeParse({ ...validManifest, ...overrides }).success).toBe(false);
		}
	});
});
