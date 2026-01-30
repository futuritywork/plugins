export type Next = (req: Request) => Promise<Response | undefined>;
export type Middleware = (req: Request, next: Next) => Promise<Response | undefined>;
export type AuthMiddleware = (req: Request) => Promise<boolean> | boolean;

export interface WellKnownEntry {
	body: unknown;
	headers?: Record<string, string>;
}

// Chained Auth Session Types

export type SessionState = "pending" | "active" | "expired" | "revoked";

export interface EncryptedToken {
	ciphertext: string;
	iv: string;
	tag: string;
}

export interface Session {
	id: string;
	platformId: string; // Platform that created this session (from JWT iss claim)
	userId: string;
	organizationId?: string;
	email?: string;
	displayName?: string;
	state: SessionState;
	externalTokens?: Record<string, EncryptedToken>;
	platformState: string;
	platformCallback: string;
	createdAt: Date;
	expiresAt?: Date;
}

export interface PendingSession {
	id: string;
	platformId: string; // Platform that created this session (from JWT iss claim)
	userId: string;
	organizationId?: string;
	email?: string;
	displayName?: string;
	state: "pending";
	platformState: string;
	platformCallback: string;
	createdAt: Date;
	expiresAt?: Date;
}

export interface SessionStore {
	create(session: PendingSession): Promise<void>;
	get(sessionId: string): Promise<Session | null>;
	update(sessionId: string, updates: Partial<Session>): Promise<void>;
	delete(sessionId: string): Promise<void>;
}

export interface UserContext {
	platform_id: string; // Platform identifier (from JWT iss claim)
	user_id: string;
	email?: string;
	organization_id?: string;
	display_name?: string;
}

export interface ChainedAuthHandlers {
	onAuthorize(
		userContext: UserContext,
		platformState: string,
		platformCallback: string
	): Promise<Response>;
	onCallback(req: Request): Promise<Response>;
	onToken?(req: Request): Promise<Response>;
}

export interface ChainedAuthConfig {
	sessionStore: SessionStore;
	handlers: ChainedAuthHandlers;
	platformJwksUrl: string;
	pluginSigningKey: string;
	/** Maximum age for platform assertions in seconds (default: 30) */
	assertionMaxAge?: number;
}

/**
 * Platform assertion claims for request binding.
 * Platform must sign a JWT with these claims on each MCP request.
 */
export interface PlatformAssertionClaims {
	/** Issued at timestamp */
	iat: number;
	/** Platform identifier (must match session's platformId) */
	iss: string;
	/** Access token hash - SHA-256 hash of the plugin token, base64url encoded */
	ath: string;
	/** Request hash - SHA-256 hash of method + path + body, base64url encoded */
	req_hash: string;
}

/**
 * Verified platform assertion result
 */
export interface VerifiedPlatformAssertion {
	platformId: string;
	accessTokenHash: string;
	requestHash: string;
	issuedAt: Date;
}

