import * as jose from "jose";
import type {
	ChainedAuthConfig,
	PendingSession,
	Session,
	SessionStore,
	UserContext,
	VerifiedPlatformAssertion,
} from "./types";

// In-memory JWKS cache (keyed by URL)
const jwksCache = new Map<string, { jwks: jose.JSONWebKeySet; expiry: number }>();
const JWKS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Clear the JWKS cache (useful for testing)
 */
export function clearJwksCache(): void {
	jwksCache.clear();
}

/**
 * Fetch and cache platform JWKS for JWT verification
 */
async function fetchPlatformJwks(jwksUrl: string): Promise<jose.JSONWebKeySet> {
	const now = Date.now();
	const cached = jwksCache.get(jwksUrl);
	if (cached && now < cached.expiry) {
		return cached.jwks;
	}

	const response = await fetch(jwksUrl);
	if (!response.ok) {
		throw new Error(`Failed to fetch JWKS: ${response.status}`);
	}

	const jwks = (await response.json()) as jose.JSONWebKeySet;
	jwksCache.set(jwksUrl, { jwks, expiry: now + JWKS_CACHE_TTL });
	return jwks;
}

/**
 * Validate a user context JWT from the platform
 */
export async function validateUserContextJwt(
	token: string,
	jwksUrl: string
): Promise<UserContext> {
	const jwks = await fetchPlatformJwks(jwksUrl);
	const keyStore = jose.createLocalJWKSet(jwks);

	const { payload } = await jose.jwtVerify(token, keyStore, {
		algorithms: ["RS256", "ES256", "EdDSA"],
		maxTokenAge: "60s", // JWT must be short-lived
	});

	// Validate required claims
	if (!payload.iss) {
		throw new Error("Missing platform_id (iss) claim");
	}
	if (!payload.sub) {
		throw new Error("Missing user_id (sub) claim");
	}

	return {
		platform_id: payload.iss,
		user_id: payload.sub,
		email: payload.email as string | undefined,
		organization_id: payload.org_id as string | undefined,
		display_name: payload.name as string | undefined,
	};
}

/**
 * Generate a plugin token (signed JWT) for the session
 */
export async function generatePluginToken(
	sessionId: string,
	platformId: string,
	signingKey: string,
	options?: {
		expiresIn?: string;
		issuer?: string;
	}
): Promise<string> {
	const privateKey = await jose.importPKCS8(signingKey, "EdDSA");

	const jwt = await new jose.SignJWT({
		sid: sessionId,
		pid: platformId, // Platform that owns this session
	})
		.setProtectedHeader({ alg: "EdDSA" })
		.setIssuedAt()
		.setExpirationTime(options?.expiresIn ?? "1h")
		.setIssuer(options?.issuer ?? "futurity-plugin")
		.sign(privateKey);

	return jwt;
}

/**
 * Validate a plugin token
 */
export async function validatePluginToken(
	token: string,
	publicKey: string
): Promise<{ sessionId: string; platformId: string }> {
	const key = await jose.importSPKI(publicKey, "EdDSA");

	const { payload } = await jose.jwtVerify(token, key, {
		algorithms: ["EdDSA"],
	});

	if (!payload.sid || typeof payload.sid !== "string") {
		throw new Error("Missing session ID (sid) claim");
	}
	if (!payload.pid || typeof payload.pid !== "string") {
		throw new Error("Missing platform ID (pid) claim");
	}

	return { sessionId: payload.sid, platformId: payload.pid };
}

/**
 * Generate a refresh token for token refresh flow
 */
export async function generateRefreshToken(
	sessionId: string,
	platformId: string,
	signingKey: string,
	options?: {
		expiresIn?: string;
		issuer?: string;
	}
): Promise<string> {
	const privateKey = await jose.importPKCS8(signingKey, "EdDSA");

	const jwt = await new jose.SignJWT({
		sid: sessionId,
		pid: platformId,
		type: "refresh",
	})
		.setProtectedHeader({ alg: "EdDSA" })
		.setIssuedAt()
		.setExpirationTime(options?.expiresIn ?? "7d")
		.setIssuer(options?.issuer ?? "futurity-plugin")
		.sign(privateKey);

	return jwt;
}

// State parameter helpers for CSRF prevention

/**
 * Generate a state parameter that chains platform state with plugin state
 */
export function generateChainedState(
	platformState: string,
	pluginSessionId: string
): string {
	const stateData = {
		platform: platformState,
		session: pluginSessionId,
		nonce: crypto.randomUUID(),
	};
	return Buffer.from(JSON.stringify(stateData)).toString("base64url");
}

/**
 * Parse a chained state parameter
 */
export function parseChainedState(state: string): {
	platform: string;
	session: string;
	nonce: string;
} {
	try {
		const decoded = Buffer.from(state, "base64url").toString("utf-8");
		const parsed = JSON.parse(decoded);
		if (!parsed.platform || !parsed.session || !parsed.nonce) {
			throw new Error("Invalid state structure");
		}
		return parsed;
	} catch {
		throw new Error("Invalid state parameter");
	}
}

// Session state machine

/**
 * Create a pending session
 */
export function createPendingSession(
	userContext: UserContext,
	platformState: string,
	platformCallback: string,
	options?: { expiresIn?: number }
): PendingSession {
	const now = new Date();
	const expiresAt = options?.expiresIn
		? new Date(now.getTime() + options.expiresIn)
		: undefined;

	return {
		id: crypto.randomUUID(),
		platformId: userContext.platform_id,
		userId: userContext.user_id,
		organizationId: userContext.organization_id,
		email: userContext.email,
		displayName: userContext.display_name,
		state: "pending",
		platformState,
		platformCallback,
		createdAt: now,
		expiresAt,
	};
}

/**
 * Activate a session (transition from pending to active)
 */
export function activateSession(
	session: Session,
	externalTokens?: Record<string, unknown>
): Partial<Session> {
	if (session.state !== "pending") {
		throw new Error(`Cannot activate session in state: ${session.state}`);
	}

	return {
		state: "active",
		externalTokens: externalTokens as Session["externalTokens"],
	};
}

/**
 * Expire a session
 */
export function expireSession(session: Session): Partial<Session> {
	if (session.state === "revoked") {
		throw new Error("Cannot expire a revoked session");
	}

	return { state: "expired" };
}

/**
 * Revoke a session
 */
export function revokeSession(session: Session): Partial<Session> {
	return { state: "revoked" };
}

/**
 * Check if a session is valid for use
 */
export function isSessionValid(session: Session): boolean {
	if (session.state !== "active") {
		return false;
	}

	if (session.expiresAt && new Date() > session.expiresAt) {
		return false;
	}

	return true;
}

// Request binding helpers

/**
 * Compute SHA-256 hash of a string, returned as base64url
 */
async function sha256Base64Url(data: string): Promise<string> {
	const encoder = new TextEncoder();
	const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(data));
	return Buffer.from(hashBuffer).toString("base64url");
}

/**
 * Hash a plugin token for the `ath` (access token hash) claim
 */
export async function hashPluginToken(token: string): Promise<string> {
	return sha256Base64Url(token);
}

/**
 * Hash request details for the `req_hash` claim
 * Binds the assertion to a specific request
 */
export async function hashRequest(
	method: string,
	path: string,
	body?: string
): Promise<string> {
	const normalizedMethod = method.toUpperCase();
	const normalizedBody = body ?? "";
	const data = `${normalizedMethod}\n${path}\n${normalizedBody}`;
	return sha256Base64Url(data);
}

/**
 * Validate a platform assertion JWT for request binding
 *
 * The platform must include this assertion on each MCP request to prove:
 * 1. The request is recent (timestamp)
 * 2. The request is bound to the specific plugin token (ath)
 * 3. The request is bound to the specific HTTP request (req_hash)
 */
export async function validatePlatformAssertion(
	assertion: string,
	jwksUrl: string,
	expectedTokenHash: string,
	expectedRequestHash: string,
	options?: { maxAgeSeconds?: number }
): Promise<VerifiedPlatformAssertion> {
	const maxAge = options?.maxAgeSeconds ?? 30;

	const jwks = await fetchPlatformJwks(jwksUrl);
	const keyStore = jose.createLocalJWKSet(jwks);

	const { payload } = await jose.jwtVerify(assertion, keyStore, {
		algorithms: ["RS256", "ES256", "EdDSA"],
		maxTokenAge: `${maxAge}s`,
	});

	// Validate required claims
	if (!payload.iss) {
		throw new Error("Missing platform ID (iss) claim");
	}
	if (!payload.ath || typeof payload.ath !== "string") {
		throw new Error("Missing access token hash (ath) claim");
	}
	if (!payload.req_hash || typeof payload.req_hash !== "string") {
		throw new Error("Missing request hash (req_hash) claim");
	}
	if (!payload.iat) {
		throw new Error("Missing issued at (iat) claim");
	}

	// Verify token binding
	if (payload.ath !== expectedTokenHash) {
		throw new Error("Access token hash mismatch - assertion not bound to this token");
	}

	// Verify request binding
	if (payload.req_hash !== expectedRequestHash) {
		throw new Error("Request hash mismatch - assertion not bound to this request");
	}

	return {
		platformId: payload.iss,
		accessTokenHash: payload.ath,
		requestHash: payload.req_hash,
		issuedAt: new Date(payload.iat * 1000),
	};
}

/**
 * Validate an MCP request with platform assertion
 *
 * This is the main entry point for validating authenticated MCP requests.
 * It verifies:
 * 1. Plugin token is valid
 * 2. Platform assertion is valid and recent
 * 3. Assertion is bound to the plugin token
 * 4. Assertion is bound to this specific request
 * 5. Platform making the request matches the session's platform
 */
export async function validateAuthenticatedRequest(
	req: Request,
	pluginPublicKey: string,
	platformJwksUrl: string,
	sessionStore: SessionStore,
	options?: { assertionMaxAge?: number }
): Promise<{ session: Session; platformId: string }> {
	// Extract plugin token from Authorization header
	const authHeader = req.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) {
		throw new Error("Missing or invalid Authorization header");
	}
	const pluginToken = authHeader.slice(7);

	// Extract platform assertion from header
	const assertion = req.headers.get("x-platform-assertion");
	if (!assertion) {
		throw new Error("Missing X-Platform-Assertion header");
	}

	// Validate plugin token
	const { sessionId, platformId: tokenPlatformId } = await validatePluginToken(
		pluginToken,
		pluginPublicKey
	);

	// Compute expected hashes
	const url = new URL(req.url);
	const body = req.body ? await req.clone().text() : undefined;
	const expectedTokenHash = await hashPluginToken(pluginToken);
	const expectedRequestHash = await hashRequest(req.method, url.pathname, body);

	// Validate platform assertion
	const verifiedAssertion = await validatePlatformAssertion(
		assertion,
		platformJwksUrl,
		expectedTokenHash,
		expectedRequestHash,
		{ maxAgeSeconds: options?.assertionMaxAge }
	);

	// Verify platform matches token
	if (verifiedAssertion.platformId !== tokenPlatformId) {
		throw new Error("Platform ID mismatch between assertion and token");
	}

	// Get session
	const session = await sessionStore.get(sessionId);
	if (!session) {
		throw new Error("Session not found");
	}

	// Verify platform matches session
	if (session.platformId !== verifiedAssertion.platformId) {
		throw new Error("Platform ID mismatch - session belongs to different platform");
	}

	// Verify session is valid
	if (!isSessionValid(session)) {
		throw new Error("Session is not active or has expired");
	}

	return { session, platformId: verifiedAssertion.platformId };
}

// In-memory session store implementation for development/testing

export class InMemorySessionStore implements SessionStore {
	private sessions = new Map<string, Session>();

	async create(session: PendingSession): Promise<void> {
		this.sessions.set(session.id, session as Session);
	}

	async get(sessionId: string): Promise<Session | null> {
		return this.sessions.get(sessionId) ?? null;
	}

	async update(sessionId: string, updates: Partial<Session>): Promise<void> {
		const session = this.sessions.get(sessionId);
		if (!session) {
			throw new Error(`Session not found: ${sessionId}`);
		}
		this.sessions.set(sessionId, { ...session, ...updates });
	}

	async delete(sessionId: string): Promise<void> {
		this.sessions.delete(sessionId);
	}

	// Helper for testing
	clear(): void {
		this.sessions.clear();
	}
}

// Chained auth route handler

export function createChainedAuthRouter(config: ChainedAuthConfig) {
	return {
		async handleAuthorize(req: Request): Promise<Response> {
			const url = new URL(req.url);

			// Extract JWT from query param or authorization header
			const token =
				url.searchParams.get("token") ??
				req.headers.get("authorization")?.replace("Bearer ", "");

			if (!token) {
				return new Response(
					JSON.stringify({ error: "missing_token", error_description: "User context token required" }),
					{ status: 400, headers: { "Content-Type": "application/json" } }
				);
			}

			// Validate user context JWT
			let userContext: UserContext;
			try {
				userContext = await validateUserContextJwt(token, config.platformJwksUrl);
			} catch (error) {
				return new Response(
					JSON.stringify({
						error: "invalid_token",
						error_description: error instanceof Error ? error.message : "Invalid token",
					}),
					{ status: 401, headers: { "Content-Type": "application/json" } }
				);
			}

			// Extract platform state and callback
			const platformState = url.searchParams.get("state");
			const platformCallback = url.searchParams.get("redirect_uri");

			if (!platformState || !platformCallback) {
				return new Response(
					JSON.stringify({
						error: "invalid_request",
						error_description: "Missing state or redirect_uri",
					}),
					{ status: 400, headers: { "Content-Type": "application/json" } }
				);
			}

			// Delegate to handler
			return config.handlers.onAuthorize(userContext, platformState, platformCallback);
		},

		async handleCallback(req: Request): Promise<Response> {
			return config.handlers.onCallback(req);
		},

		async handleToken(req: Request): Promise<Response> {
			if (!config.handlers.onToken) {
				return new Response(
					JSON.stringify({ error: "unsupported_grant_type" }),
					{ status: 400, headers: { "Content-Type": "application/json" } }
				);
			}
			return config.handlers.onToken(req);
		},
	};
}
