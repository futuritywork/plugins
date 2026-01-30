import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import * as jose from "jose";

// Type alias for jose key types
type JoseKey = CryptoKey | Uint8Array;
import {
	createChainedAuthRouter,
	createPendingSession,
	activateSession,
	expireSession,
	revokeSession,
	isSessionValid,
	generateChainedState,
	parseChainedState,
	generatePluginToken,
	validatePluginToken,
	generateRefreshToken,
	InMemorySessionStore,
	clearJwksCache,
	hashPluginToken,
	hashRequest,
	validatePlatformAssertion,
	validateAuthenticatedRequest,
} from "./chainedAuth";
import { mcp } from "./app";
import type {
	ChainedAuthHandlers,
	Session,
	UserContext,
} from "./types";

// ============================================================================
// Test Key Generation Helpers
// ============================================================================

async function generateTestKeyPair() {
	const { publicKey, privateKey } = await jose.generateKeyPair("EdDSA", {
		extractable: true,
	});
	const privatePem = await jose.exportPKCS8(privateKey);
	const publicPem = await jose.exportSPKI(publicKey);
	return { privateKey: privatePem, publicKey: publicPem };
}

async function generateRSAKeyPair() {
	const { publicKey, privateKey } = await jose.generateKeyPair("RS256", {
		extractable: true,
	});
	return { publicKey, privateKey };
}

// ============================================================================
// State Parameter Tests
// ============================================================================

describe("State Parameters", () => {
	test("generateChainedState creates valid base64url encoded state", () => {
		const state = generateChainedState("platform-state-123", "session-456");
		expect(state).toBeString();
		// Should be valid base64url
		expect(() => Buffer.from(state, "base64url")).not.toThrow();
	});

	test("parseChainedState decodes state correctly", () => {
		const platformState = "my-platform-state";
		const sessionId = "my-session-id";
		const state = generateChainedState(platformState, sessionId);

		const parsed = parseChainedState(state);
		expect(parsed.platform).toBe(platformState);
		expect(parsed.session).toBe(sessionId);
		expect(parsed.nonce).toBeString();
		expect(parsed.nonce.length).toBeGreaterThan(0);
	});

	test("parseChainedState throws for invalid state", () => {
		expect(() => parseChainedState("not-valid-base64url!@#")).toThrow(
			"Invalid state parameter"
		);
		expect(() => parseChainedState("")).toThrow("Invalid state parameter");
	});

	test("parseChainedState throws for missing fields", () => {
		const incomplete = Buffer.from(
			JSON.stringify({ platform: "x" })
		).toString("base64url");
		expect(() => parseChainedState(incomplete)).toThrow(
			"Invalid state parameter"
		);
	});

	test("each state has a unique nonce", () => {
		const state1 = generateChainedState("p", "s");
		const state2 = generateChainedState("p", "s");
		const parsed1 = parseChainedState(state1);
		const parsed2 = parseChainedState(state2);
		expect(parsed1.nonce).not.toBe(parsed2.nonce);
	});
});

// ============================================================================
// Session State Machine Tests
// ============================================================================

describe("Session State Machine", () => {
	const userContext: UserContext = {
		platform_id: "https://platform.example.com",
		user_id: "user-123",
		email: "test@example.com",
		organization_id: "org-456",
		display_name: "Test User",
	};

	test("createPendingSession creates session with pending state", () => {
		const session = createPendingSession(
			userContext,
			"platform-state",
			"https://platform.com/callback"
		);

		expect(session.id).toBeString();
		expect(session.userId).toBe("user-123");
		expect(session.email).toBe("test@example.com");
		expect(session.organizationId).toBe("org-456");
		expect(session.displayName).toBe("Test User");
		expect(session.state).toBe("pending");
		expect(session.platformState).toBe("platform-state");
		expect(session.platformCallback).toBe("https://platform.com/callback");
		expect(session.createdAt).toBeInstanceOf(Date);
	});

	test("createPendingSession with expiry", () => {
		const session = createPendingSession(
			userContext,
			"state",
			"https://callback.com",
			{ expiresIn: 3600000 }
		);

		expect(session.expiresAt).toBeInstanceOf(Date);
		expect(session.expiresAt!.getTime()).toBeGreaterThan(Date.now());
	});

	test("activateSession transitions from pending to active", () => {
		const pendingSession = createPendingSession(
			userContext,
			"state",
			"https://callback.com"
		) as Session;

		const updates = activateSession(pendingSession, {
			monday: { ciphertext: "encrypted-token", iv: "test-iv", tag: "test-tag" },
		});

		expect(updates.state).toBe("active");
		expect(updates.externalTokens).toEqual({
			monday: { ciphertext: "encrypted-token", iv: "test-iv", tag: "test-tag" },
		});
	});

	test("activateSession throws for non-pending session", () => {
		const activeSession: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "active",
		};

		expect(() => activateSession(activeSession)).toThrow(
			"Cannot activate session in state: active"
		);
	});

	test("expireSession transitions to expired", () => {
		const session: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "active",
		};

		const updates = expireSession(session);
		expect(updates.state).toBe("expired");
	});

	test("expireSession throws for revoked session", () => {
		const session: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "revoked",
		};

		expect(() => expireSession(session)).toThrow(
			"Cannot expire a revoked session"
		);
	});

	test("revokeSession transitions to revoked", () => {
		const session: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "active",
		};

		const updates = revokeSession(session);
		expect(updates.state).toBe("revoked");
	});

	test("isSessionValid returns true for active non-expired session", () => {
		const session: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "active",
		};

		expect(isSessionValid(session)).toBe(true);
	});

	test("isSessionValid returns false for pending session", () => {
		const session = createPendingSession(
			userContext,
			"state",
			"https://callback.com"
		) as Session;

		expect(isSessionValid(session)).toBe(false);
	});

	test("isSessionValid returns false for expired session", () => {
		const session: Session = {
			...createPendingSession(userContext, "state", "https://callback.com"),
			state: "active",
			expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
		};

		expect(isSessionValid(session)).toBe(false);
	});
});

// ============================================================================
// InMemorySessionStore Tests
// ============================================================================

describe("InMemorySessionStore", () => {
	let store: InMemorySessionStore;

	beforeEach(() => {
		store = new InMemorySessionStore();
	});

	const userContext: UserContext = {
		platform_id: "https://platform.example.com",
		user_id: "user-123",
	};

	test("create and get session", async () => {
		const session = createPendingSession(
			userContext,
			"state",
			"https://callback.com"
		);
		await store.create(session);

		const retrieved = await store.get(session.id);
		expect(retrieved).not.toBeNull();
		expect(retrieved!.id).toBe(session.id);
		expect(retrieved!.userId).toBe("user-123");
	});

	test("get returns null for non-existent session", async () => {
		const result = await store.get("non-existent-id");
		expect(result).toBeNull();
	});

	test("update session", async () => {
		const session = createPendingSession(
			userContext,
			"state",
			"https://callback.com"
		);
		await store.create(session);

		await store.update(session.id, { state: "active" });

		const updated = await store.get(session.id);
		expect(updated!.state).toBe("active");
	});

	test("update throws for non-existent session", async () => {
		await expect(
			store.update("non-existent", { state: "active" })
		).rejects.toThrow("Session not found");
	});

	test("delete session", async () => {
		const session = createPendingSession(
			userContext,
			"state",
			"https://callback.com"
		);
		await store.create(session);
		await store.delete(session.id);

		const result = await store.get(session.id);
		expect(result).toBeNull();
	});

	test("clear removes all sessions", async () => {
		const session1 = createPendingSession(
			userContext,
			"state1",
			"https://callback.com"
		);
		const session2 = createPendingSession(
			userContext,
			"state2",
			"https://callback.com"
		);
		await store.create(session1);
		await store.create(session2);

		store.clear();

		expect(await store.get(session1.id)).toBeNull();
		expect(await store.get(session2.id)).toBeNull();
	});
});

// ============================================================================
// Plugin Token Tests
// ============================================================================

describe("Plugin Tokens", () => {
	const testPlatformId = "https://platform.example.com";

	test("generatePluginToken creates valid JWT", async () => {
		const { privateKey } = await generateTestKeyPair();

		const token = await generatePluginToken("session-123", testPlatformId, privateKey);

		expect(token).toBeString();
		const parts = token.split(".");
		expect(parts).toHaveLength(3);
	});

	test("validatePluginToken extracts session ID and platform ID", async () => {
		const { privateKey, publicKey } = await generateTestKeyPair();

		const token = await generatePluginToken("session-456", testPlatformId, privateKey);
		const result = await validatePluginToken(token, publicKey);

		expect(result.sessionId).toBe("session-456");
		expect(result.platformId).toBe(testPlatformId);
	});

	test("validatePluginToken rejects invalid token", async () => {
		const { publicKey } = await generateTestKeyPair();

		await expect(validatePluginToken("invalid.token.here", publicKey)).rejects.toThrow();
	});

	test("validatePluginToken rejects wrong key", async () => {
		const keys1 = await generateTestKeyPair();
		const keys2 = await generateTestKeyPair();

		const token = await generatePluginToken("session-123", testPlatformId, keys1.privateKey);
		await expect(validatePluginToken(token, keys2.publicKey)).rejects.toThrow();
	});

	test("generateRefreshToken creates refresh token with type claim", async () => {
		const { privateKey, publicKey } = await generateTestKeyPair();

		const token = await generateRefreshToken("session-789", testPlatformId, privateKey);
		const key = await jose.importSPKI(publicKey, "EdDSA");
		const { payload } = await jose.jwtVerify(token, key);

		expect(payload.sid).toBe("session-789");
		expect(payload.pid).toBe(testPlatformId);
		expect(payload.type).toBe("refresh");
	});

	test("plugin token expires", async () => {
		const { privateKey, publicKey } = await generateTestKeyPair();

		const token = await generatePluginToken("session-123", testPlatformId, privateKey, {
			expiresIn: "1s",
		});

		// Wait for expiration
		await new Promise((resolve) => setTimeout(resolve, 1100));

		await expect(validatePluginToken(token, publicKey)).rejects.toThrow();
	});
});

// ============================================================================
// Request Binding Tests
// ============================================================================

describe("Request Binding", () => {
	test("hashPluginToken produces consistent hash", async () => {
		const token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test.signature";

		const hash1 = await hashPluginToken(token);
		const hash2 = await hashPluginToken(token);

		expect(hash1).toBeString();
		expect(hash1).toBe(hash2);
		// Should be base64url encoded
		expect(hash1).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	test("hashPluginToken produces different hashes for different tokens", async () => {
		const token1 = "token-1";
		const token2 = "token-2";

		const hash1 = await hashPluginToken(token1);
		const hash2 = await hashPluginToken(token2);

		expect(hash1).not.toBe(hash2);
	});

	test("hashRequest produces consistent hash", async () => {
		const hash1 = await hashRequest("POST", "/mcp", '{"jsonrpc":"2.0"}');
		const hash2 = await hashRequest("POST", "/mcp", '{"jsonrpc":"2.0"}');

		expect(hash1).toBeString();
		expect(hash1).toBe(hash2);
	});

	test("hashRequest normalizes HTTP method to uppercase", async () => {
		const hash1 = await hashRequest("post", "/mcp", "body");
		const hash2 = await hashRequest("POST", "/mcp", "body");

		expect(hash1).toBe(hash2);
	});

	test("hashRequest handles undefined body", async () => {
		const hash1 = await hashRequest("GET", "/mcp");
		const hash2 = await hashRequest("GET", "/mcp", undefined);
		const hash3 = await hashRequest("GET", "/mcp", "");

		expect(hash1).toBe(hash2);
		expect(hash1).toBe(hash3);
	});

	test("hashRequest produces different hashes for different requests", async () => {
		const hash1 = await hashRequest("GET", "/mcp");
		const hash2 = await hashRequest("POST", "/mcp");
		const hash3 = await hashRequest("POST", "/mcp", "body");
		const hash4 = await hashRequest("POST", "/other");

		expect(hash1).not.toBe(hash2);
		expect(hash2).not.toBe(hash3);
		expect(hash3).not.toBe(hash4);
	});
});

describe("Platform Assertion Validation", () => {
	let platformKeyPair: { publicKey: JoseKey; privateKey: JoseKey };
	let jwksServer: ReturnType<typeof Bun.serve> | null = null;

	beforeEach(async () => {
		clearJwksCache();
		platformKeyPair = await generateRSAKeyPair();
	});

	afterEach(() => {
		jwksServer?.stop();
		jwksServer = null;
	});

	async function createJwksServer() {
		const jwk = await jose.exportJWK(platformKeyPair.publicKey);
		jwk.kid = "test-key-1";
		jwk.alg = "RS256";

		const srv = Bun.serve({
			port: 0,
			fetch: () =>
				new Response(JSON.stringify({ keys: [jwk] }), {
					headers: { "Content-Type": "application/json" },
				}),
		});
		jwksServer = srv;
		return `http://localhost:${srv.port}/.well-known/jwks.json`;
	}

	async function createPlatformAssertion(claims: {
		ath: string;
		req_hash: string;
		iss?: string;
		iat?: number;
	}) {
		const jwt = new jose.SignJWT({
			ath: claims.ath,
			req_hash: claims.req_hash,
		})
			.setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
			.setIssuer(claims.iss ?? "https://platform.example.com")
			.setIssuedAt(claims.iat);

		return jwt.sign(platformKeyPair.privateKey);
	}

	test("validates correct platform assertion", async () => {
		const jwksUrl = await createJwksServer();

		const tokenHash = await hashPluginToken("test-token");
		const requestHash = await hashRequest("POST", "/mcp", "body");

		const assertion = await createPlatformAssertion({
			ath: tokenHash,
			req_hash: requestHash,
		});

		const result = await validatePlatformAssertion(
			assertion,
			jwksUrl,
			tokenHash,
			requestHash
		);

		expect(result.platformId).toBe("https://platform.example.com");
		expect(result.accessTokenHash).toBe(tokenHash);
		expect(result.requestHash).toBe(requestHash);
		expect(result.issuedAt).toBeInstanceOf(Date);
	});

	test("rejects assertion with wrong token hash", async () => {
		const jwksUrl = await createJwksServer();

		const tokenHash = await hashPluginToken("test-token");
		const wrongTokenHash = await hashPluginToken("different-token");
		const requestHash = await hashRequest("POST", "/mcp", "body");

		const assertion = await createPlatformAssertion({
			ath: wrongTokenHash,
			req_hash: requestHash,
		});

		await expect(
			validatePlatformAssertion(assertion, jwksUrl, tokenHash, requestHash)
		).rejects.toThrow("Access token hash mismatch");
	});

	test("rejects assertion with wrong request hash", async () => {
		const jwksUrl = await createJwksServer();

		const tokenHash = await hashPluginToken("test-token");
		const requestHash = await hashRequest("POST", "/mcp", "body");
		const wrongRequestHash = await hashRequest("POST", "/mcp", "different-body");

		const assertion = await createPlatformAssertion({
			ath: tokenHash,
			req_hash: wrongRequestHash,
		});

		await expect(
			validatePlatformAssertion(assertion, jwksUrl, tokenHash, requestHash)
		).rejects.toThrow("Request hash mismatch");
	});

	test("rejects expired assertion", async () => {
		const jwksUrl = await createJwksServer();

		const tokenHash = await hashPluginToken("test-token");
		const requestHash = await hashRequest("POST", "/mcp", "body");

		// Create assertion with old timestamp (60 seconds ago)
		const assertion = await createPlatformAssertion({
			ath: tokenHash,
			req_hash: requestHash,
			iat: Math.floor(Date.now() / 1000) - 60,
		});

		await expect(
			validatePlatformAssertion(assertion, jwksUrl, tokenHash, requestHash, {
				maxAgeSeconds: 30,
			})
		).rejects.toThrow();
	});
});

// ============================================================================
// Chained Auth Router Tests
// ============================================================================

describe("Chained Auth Router", () => {
	let platformKeyPair: { publicKey: JoseKey; privateKey: JoseKey };
	let pluginKeyPair: { privateKey: string; publicKey: string };
	let sessionStore: InMemorySessionStore;
	let jwksServer: ReturnType<typeof Bun.serve> | null = null;

	beforeEach(async () => {
		clearJwksCache();
		platformKeyPair = await generateRSAKeyPair();
		pluginKeyPair = await generateTestKeyPair();
		sessionStore = new InMemorySessionStore();
	});

	afterEach(() => {
		jwksServer?.stop();
		jwksServer = null;
	});

	async function createJwksServer() {
		const jwk = await jose.exportJWK(platformKeyPair.publicKey);
		jwk.kid = "test-key-1";
		jwk.alg = "RS256";

		const server = Bun.serve({
			port: 0, // Random available port
			fetch: () =>
				new Response(JSON.stringify({ keys: [jwk] }), {
					headers: { "Content-Type": "application/json" },
				}),
		});
		jwksServer = server;
		return `http://localhost:${server.port}/.well-known/jwks.json`;
	}

	async function createUserContextJwt(userContext: Partial<UserContext>) {
		return new jose.SignJWT({
			sub: userContext.user_id,
			email: userContext.email,
			org_id: userContext.organization_id,
			name: userContext.display_name,
		})
			.setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
			.setIssuer(userContext.platform_id ?? "https://test-platform.example.com")
			.setIssuedAt()
			.setExpirationTime("60s")
			.sign(platformKeyPair.privateKey);
	}

	test("handleAuthorize returns error for missing token", async () => {
		const jwksUrl = await createJwksServer();

		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async () => new Response("OK"),
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request(
			"http://localhost/auth/authorize?state=abc&redirect_uri=https://platform.com/cb"
		);
		const res = await router.handleAuthorize(req);

		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("missing_token");
	});

	test("handleAuthorize returns error for invalid JWT", async () => {
		const jwksUrl = await createJwksServer();

		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async () => new Response("OK"),
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request(
			"http://localhost/auth/authorize?token=invalid.jwt.token&state=abc&redirect_uri=https://platform.com/cb"
		);
		const res = await router.handleAuthorize(req);

		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("invalid_token");
	});

	test("handleAuthorize returns error for missing state or redirect_uri", async () => {
		const jwksUrl = await createJwksServer();
		const token = await createUserContextJwt({ user_id: "user-123" });

		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async () => new Response("OK"),
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request(
			`http://localhost/auth/authorize?token=${token}`
		);
		const res = await router.handleAuthorize(req);

		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("invalid_request");
	});

	test("handleAuthorize delegates to handler with valid JWT", async () => {
		const jwksUrl = await createJwksServer();
		const token = await createUserContextJwt({
			user_id: "user-123",
			email: "test@example.com",
		});

		let receivedUserContext: UserContext | undefined;
		let receivedState: string | undefined;
		let receivedCallback: string | undefined;

		const handlers: ChainedAuthHandlers = {
			onAuthorize: async (userContext, state, callback) => {
				receivedUserContext = userContext;
				receivedState = state;
				receivedCallback = callback;
				return new Response(null, {
					status: 302,
					headers: { Location: "https://external.oauth.com/authorize" },
				});
			},
			onCallback: async () => new Response("OK"),
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request(
			`http://localhost/auth/authorize?token=${token}&state=platform-state&redirect_uri=https://platform.com/callback`
		);
		const res = await router.handleAuthorize(req);

		expect(res.status).toBe(302);
		expect(receivedUserContext).toBeDefined();
		expect(receivedUserContext!.user_id).toBe("user-123");
		expect(receivedUserContext!.email).toBe("test@example.com");
		expect(receivedState).toBe("platform-state");
		expect(receivedCallback).toBe("https://platform.com/callback");
	});

	test("handleCallback delegates to handler", async () => {
		const jwksUrl = await createJwksServer();

		let callbackCalled = false;
		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async (req) => {
				callbackCalled = true;
				const url = new URL(req.url);
				return new Response(`code=${url.searchParams.get("code")}`);
			},
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request(
			"http://localhost/auth/callback?code=auth-code-123&state=some-state"
		);
		const res = await router.handleCallback(req);

		expect(callbackCalled).toBe(true);
		expect(await res.text()).toBe("code=auth-code-123");
	});

	test("handleToken returns error when onToken not implemented", async () => {
		const jwksUrl = await createJwksServer();

		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async () => new Response("OK"),
			// onToken not provided
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request("http://localhost/auth/token", {
			method: "POST",
			body: "grant_type=refresh_token&refresh_token=xxx",
		});
		const res = await router.handleToken(req);

		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("unsupported_grant_type");
	});

	test("handleToken delegates to handler when implemented", async () => {
		const jwksUrl = await createJwksServer();

		let tokenCalled = false;
		const handlers: ChainedAuthHandlers = {
			onAuthorize: async () => new Response("OK"),
			onCallback: async () => new Response("OK"),
			onToken: async () => {
				tokenCalled = true;
				return new Response(
					JSON.stringify({ access_token: "new-token", token_type: "Bearer" }),
					{ headers: { "Content-Type": "application/json" } }
				);
			},
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		const req = new Request("http://localhost/auth/token", {
			method: "POST",
			body: "grant_type=refresh_token&refresh_token=xxx",
		});
		const res = await router.handleToken(req);

		expect(tokenCalled).toBe(true);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { access_token: string };
		expect(body.access_token).toBe("new-token");
	});
});

// ============================================================================
// HTTP Transport Auth Route Integration Tests
// ============================================================================

describe("HTTP Transport Auth Routes", () => {
	let app: ReturnType<typeof mcp>;
	let server: Awaited<ReturnType<typeof app.listen>> | null = null;
	let platformKeyPair: { publicKey: JoseKey; privateKey: JoseKey };
	let pluginKeyPair: { privateKey: string; publicKey: string };
	let sessionStore: InMemorySessionStore;
	let jwksServer: ReturnType<typeof Bun.serve> | null = null;

	beforeEach(async () => {
		clearJwksCache();
		platformKeyPair = await generateRSAKeyPair();
		pluginKeyPair = await generateTestKeyPair();
		sessionStore = new InMemorySessionStore();
	});

	afterEach(async () => {
		await server?.stop();
		server = null;
		jwksServer?.stop();
		jwksServer = null;
	});

	async function createJwksServer() {
		const jwk = await jose.exportJWK(platformKeyPair.publicKey);
		jwk.kid = "test-key-1";
		jwk.alg = "RS256";

		const srv = Bun.serve({
			port: 0,
			fetch: () =>
				new Response(JSON.stringify({ keys: [jwk] }), {
					headers: { "Content-Type": "application/json" },
				}),
		});
		jwksServer = srv;
		return `http://localhost:${srv.port}/.well-known/jwks.json`;
	}

	async function createUserContextJwt(userContext: Partial<UserContext>) {
		return new jose.SignJWT({
			sub: userContext.user_id,
			email: userContext.email,
		})
			.setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
			.setIssuer(userContext.platform_id ?? "https://test-platform.example.com")
			.setIssuedAt()
			.setExpirationTime("60s")
			.sign(platformKeyPair.privateKey);
	}

	test("server routes /auth/authorize to chained auth handler", async () => {
		const jwksUrl = await createJwksServer();
		const testPort = 9876; // Use different port to avoid conflicts

		let authorizeCalled = false;
		app = mcp({
			name: "test-server",
			version: "1.0.0",
			chainedAuth: {
				sessionStore,
				platformJwksUrl: jwksUrl,
				pluginSigningKey: pluginKeyPair.privateKey,
				handlers: {
					onAuthorize: async () => {
						authorizeCalled = true;
						return new Response(null, {
							status: 302,
							headers: { Location: "https://external.com/oauth" },
						});
					},
					onCallback: async () => new Response("callback"),
				},
			},
		});

		server = await app.listen(testPort, "http");

		const token = await createUserContextJwt({ user_id: "test-user" });
		const res = await fetch(
			`http://localhost:${testPort}/auth/authorize?token=${token}&state=test&redirect_uri=https://platform.com/cb`,
			{ redirect: "manual" }
		);

		expect(authorizeCalled).toBe(true);
		expect(res.status).toBe(302);
		expect(res.headers.get("Location")).toBe("https://external.com/oauth");
	});

	test("server routes /auth/callback to chained auth handler", async () => {
		const jwksUrl = await createJwksServer();
		const testPort = 9877; // Use different port to avoid conflicts

		let callbackCalled = false;
		app = mcp({
			name: "test-server",
			version: "1.0.0",
			chainedAuth: {
				sessionStore,
				platformJwksUrl: jwksUrl,
				pluginSigningKey: pluginKeyPair.privateKey,
				handlers: {
					onAuthorize: async () => new Response("authorize"),
					onCallback: async () => {
						callbackCalled = true;
						return new Response(null, {
							status: 302,
							headers: { Location: "https://platform.com/callback?token=xyz" },
						});
					},
				},
			},
		});

		server = await app.listen(testPort, "http");

		const res = await fetch(
			`http://localhost:${testPort}/auth/callback?code=external-code&state=encoded-state`,
			{ redirect: "manual" }
		);

		expect(callbackCalled).toBe(true);
		expect(res.status).toBe(302);
	});

	test("server routes /auth/token to chained auth handler", async () => {
		const jwksUrl = await createJwksServer();
		const testPort = 9878; // Use different port to avoid conflicts

		let tokenCalled = false;
		app = mcp({
			name: "test-server",
			version: "1.0.0",
			chainedAuth: {
				sessionStore,
				platformJwksUrl: jwksUrl,
				pluginSigningKey: pluginKeyPair.privateKey,
				handlers: {
					onAuthorize: async () => new Response("authorize"),
					onCallback: async () => new Response("callback"),
					onToken: async () => {
						tokenCalled = true;
						return new Response(
							JSON.stringify({
								access_token: "refreshed-token",
								token_type: "Bearer",
							}),
							{ headers: { "Content-Type": "application/json" } }
						);
					},
				},
			},
		});

		server = await app.listen(testPort, "http");

		const res = await fetch(`http://localhost:${testPort}/auth/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "grant_type=refresh_token&refresh_token=old-token",
		});

		expect(tokenCalled).toBe(true);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { access_token: string };
		expect(body.access_token).toBe("refreshed-token");
	});

	test("server returns 404 for unknown /auth/* paths", async () => {
		const jwksUrl = await createJwksServer();
		const testPort = 9879; // Use different port to avoid conflicts

		app = mcp({
			name: "test-server",
			version: "1.0.0",
			chainedAuth: {
				sessionStore,
				platformJwksUrl: jwksUrl,
				pluginSigningKey: pluginKeyPair.privateKey,
				handlers: {
					onAuthorize: async () => new Response("authorize"),
					onCallback: async () => new Response("callback"),
				},
			},
		});

		server = await app.listen(testPort, "http");

		const res = await fetch(`http://localhost:${testPort}/auth/unknown`);

		expect(res.status).toBe(404);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("not_found");
	});

	test("MCP endpoint still works with chained auth configured", async () => {
		const jwksUrl = await createJwksServer();
		const testPort = 9880; // Use different port to avoid conflicts

		app = mcp({
			name: "test-server",
			version: "1.0.0",
			chainedAuth: {
				sessionStore,
				platformJwksUrl: jwksUrl,
				pluginSigningKey: pluginKeyPair.privateKey,
				handlers: {
					onAuthorize: async () => new Response("authorize"),
					onCallback: async () => new Response("callback"),
				},
			},
		});

		app.tool("test_tool", {
			description: "A test tool",
			handler: async () => ({ result: "success" }),
		});

		server = await app.listen(testPort, "http");

		// Initialize MCP session
		const initRes = await fetch(`http://localhost:${testPort}/mcp`, {
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

		expect(initRes.status).toBe(200);
		expect(initRes.headers.get("mcp-session-id")).toBeString();
	});
});

// ============================================================================
// Full Auth Flow Integration Test
// ============================================================================

describe("Full Chained Auth Flow", () => {
	let platformKeyPair: { publicKey: JoseKey; privateKey: JoseKey };
	let pluginKeyPair: { privateKey: string; publicKey: string };
	let sessionStore: InMemorySessionStore;
	let jwksServer: ReturnType<typeof Bun.serve> | null = null;

	beforeEach(async () => {
		clearJwksCache();
		platformKeyPair = await generateRSAKeyPair();
		pluginKeyPair = await generateTestKeyPair();
		sessionStore = new InMemorySessionStore();
	});

	afterEach(() => {
		jwksServer?.stop();
		jwksServer = null;
	});

	async function createJwksServer() {
		const jwk = await jose.exportJWK(platformKeyPair.publicKey);
		jwk.kid = "test-key-1";
		jwk.alg = "RS256";

		const srv = Bun.serve({
			port: 0,
			fetch: () =>
				new Response(JSON.stringify({ keys: [jwk] }), {
					headers: { "Content-Type": "application/json" },
				}),
		});
		jwksServer = srv;
		return `http://localhost:${srv.port}/.well-known/jwks.json`;
	}

	test("complete auth flow: authorize -> callback -> token", async () => {
		const jwksUrl = await createJwksServer();

		// Simulate the full flow
		const handlers: ChainedAuthHandlers = {
			onAuthorize: async (userContext, platformState, platformCallback) => {
				// 1. Create pending session
				const session = createPendingSession(
					userContext,
					platformState,
					platformCallback
				);
				await sessionStore.create(session);

				// 2. Generate chained state for external OAuth
				const chainedState = generateChainedState(platformState, session.id);

				// 3. Redirect to external OAuth
				const externalAuthUrl = new URL(
					"https://external.oauth.com/authorize"
				);
				externalAuthUrl.searchParams.set("state", chainedState);
				externalAuthUrl.searchParams.set("redirect_uri", "https://plugin.com/auth/callback");

				return new Response(null, {
					status: 302,
					headers: { Location: externalAuthUrl.toString() },
				});
			},

			onCallback: async (req) => {
				const url = new URL(req.url);
				const state = url.searchParams.get("state")!;
				const code = url.searchParams.get("code")!;

				// 4. Parse chained state
				const { platform: platformState, session: sessionId } =
					parseChainedState(state);

				// 5. Get pending session
				const session = await sessionStore.get(sessionId);
				if (!session || session.state !== "pending") {
					return new Response("Invalid session", { status: 400 });
				}

				// 6. Exchange code for external token (simulated)
				const externalToken = `external-token-for-${code}`;

				// 7. Activate session with external token
				const updates = activateSession(session, {
					external: { ciphertext: externalToken, iv: "", tag: "" },
				});
				await sessionStore.update(sessionId, updates);

				// 8. Generate plugin token
				const pluginToken = await generatePluginToken(
					sessionId,
					session.platformId,
					pluginKeyPair.privateKey
				);

				// 9. Redirect back to platform
				const callbackUrl = new URL(session.platformCallback);
				callbackUrl.searchParams.set("token", pluginToken);
				callbackUrl.searchParams.set("state", platformState);

				return new Response(null, {
					status: 302,
					headers: { Location: callbackUrl.toString() },
				});
			},

			onToken: async (req) => {
				const body = await req.text();
				const params = new URLSearchParams(body);
				const refreshToken = params.get("refresh_token")!;

				// 10. Validate refresh token and get session
				const { sessionId, platformId } = await validatePluginToken(
					refreshToken,
					pluginKeyPair.publicKey
				);

				const session = await sessionStore.get(sessionId);
				if (!session || !isSessionValid(session)) {
					return new Response(
						JSON.stringify({ error: "invalid_grant" }),
						{ status: 400, headers: { "Content-Type": "application/json" } }
					);
				}

				// 11. Issue new tokens
				const newAccessToken = await generatePluginToken(
					sessionId,
					platformId,
					pluginKeyPair.privateKey,
					{ expiresIn: "1h" }
				);
				const newRefreshToken = await generateRefreshToken(
					sessionId,
					platformId,
					pluginKeyPair.privateKey
				);

				return new Response(
					JSON.stringify({
						access_token: newAccessToken,
						refresh_token: newRefreshToken,
						token_type: "Bearer",
						expires_in: 3600,
					}),
					{ headers: { "Content-Type": "application/json" } }
				);
			},
		};

		const router = createChainedAuthRouter({
			sessionStore,
			handlers,
			platformJwksUrl: jwksUrl,
			pluginSigningKey: pluginKeyPair.privateKey,
		});

		// Step 1: Platform initiates auth
		const testPlatformId = "https://test-platform.example.com";
		const userToken = await new jose.SignJWT({ sub: "user-123" })
			.setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
			.setIssuer(testPlatformId)
			.setIssuedAt()
			.setExpirationTime("60s")
			.sign(platformKeyPair.privateKey);

		const authorizeReq = new Request(
			`http://plugin.com/auth/authorize?token=${userToken}&state=platform-state-xyz&redirect_uri=https://platform.com/oauth/callback`
		);
		const authorizeRes = await router.handleAuthorize(authorizeReq);

		expect(authorizeRes.status).toBe(302);
		const externalAuthUrl = new URL(authorizeRes.headers.get("Location")!);
		expect(externalAuthUrl.hostname).toBe("external.oauth.com");
		const chainedState = externalAuthUrl.searchParams.get("state")!;

		// Step 2: External OAuth callback (simulated - user completed external auth)
		const callbackReq = new Request(
			`http://plugin.com/auth/callback?code=external-auth-code&state=${chainedState}`
		);
		const callbackRes = await router.handleCallback(callbackReq);

		expect(callbackRes.status).toBe(302);
		const platformCallbackUrl = new URL(callbackRes.headers.get("Location")!);
		expect(platformCallbackUrl.hostname).toBe("platform.com");
		expect(platformCallbackUrl.searchParams.get("state")).toBe(
			"platform-state-xyz"
		);
		const pluginToken = platformCallbackUrl.searchParams.get("token")!;

		// Verify plugin token
		const { sessionId, platformId: verifiedPlatformId } = await validatePluginToken(
			pluginToken,
			pluginKeyPair.publicKey
		);
		const session = await sessionStore.get(sessionId);
		expect(session).not.toBeNull();
		expect(session!.state).toBe("active");
		expect(session!.userId).toBe("user-123");
		expect(session!.platformId).toBe(testPlatformId);
		expect(verifiedPlatformId).toBe(testPlatformId);

		// Step 3: Token refresh
		const refreshToken = await generateRefreshToken(
			sessionId,
			testPlatformId,
			pluginKeyPair.privateKey
		);

		const tokenReq = new Request("http://plugin.com/auth/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
		});
		const tokenRes = await router.handleToken(tokenReq);

		expect(tokenRes.status).toBe(200);
		const tokenBody = (await tokenRes.json()) as {
			access_token: string;
			refresh_token: string;
			token_type: string;
		};
		expect(tokenBody.access_token).toBeString();
		expect(tokenBody.refresh_token).toBeString();
		expect(tokenBody.token_type).toBe("Bearer");

		// Verify new access token
		const { sessionId: refreshedSessionId } = await validatePluginToken(
			tokenBody.access_token,
			pluginKeyPair.publicKey
		);
		expect(refreshedSessionId).toBe(sessionId);
	});
});
