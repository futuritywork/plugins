import {
	futurityExtension,
	FuturityIdentityClaimsSchema,
	type CredentialOption,
	type Holder,
	type PluginManifest,
} from "@futurity/plugin-manifest";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";

/**
 * A Futurity deployment this plugin trusts: the `iss` its identity tokens carry and where it publishes its signing keys.
 * `https://*.futurity.work` trusts every subdomain origin with that scheme and port; its `jwksUrl` is a path resolved against the token's `iss`.
 */
export type TrustedIssuer = {
	issuer: string;
	jwksUrl: string;
};

/** One plugin deployment may serve several Futurity deployments, such as production, staging and dev. An exact issuer wins over a wildcard. */
export type FuturityOptions = {
	issuers: TrustedIssuer[];
};

/** The caller Futurity vouched for, and the credentials of the option it called with. */
export type FuturityIdentity = {
	/** The trusted Futurity deployment that issued the token. */
	issuer: string;
	org: { id: string };
	user: { id: string };
	holder: Holder;
	credentials: Record<string, string>;
};

/** An OAuth option's access token appears in `credentials` under this key. */
export const ACCESS_TOKEN_KEY = "access_token";

export type VerifiedRequest = {
	identity: FuturityIdentity;
	token: string;
	expiresAt: number;
};

function errorResponse(status: 400 | 401, error: string, description: string): Response {
	return Response.json(
		{ error, error_description: description },
		{ status, headers: status === 401 ? { "WWW-Authenticate": 'Bearer realm="futurity"' } : {} }
	);
}

function bearerToken(req: Request): string | undefined {
	const header = req.headers.get("authorization");
	const match = header?.match(/^Bearer\s+(\S+)$/i);
	return match?.[1];
}

/** Reads every declared header of the option, or names the first required one that is missing. */
function readCredentials(req: Request, option: CredentialOption): { credentials: Record<string, string> } | { missing: string } {
	const credentials: Record<string, string> = {};
	for (const field of option.fields) {
		if (field.header === undefined) continue;
		const value = req.headers.get(field.header);
		if (value !== null) credentials[field.key] = value;
		else if (field.required !== false) return { missing: field.header };
	}
	if (option.method.type === "oauth" && typeof option.method.delivery === "object") {
		const token = req.headers.get(option.method.delivery.header);
		if (token === null) return { missing: option.method.delivery.header };
		credentials[ACCESS_TOKEN_KEY] = token;
		for (const field of [...(option.method.tokenResponseFields ?? []), ...(option.method.callbackQueryFields ?? [])]) {
			const value = req.headers.get(field.header);
			if (value === null) return { missing: field.header };
			credentials[field.key] = value;
		}
	}
	return { credentials };
}

function assertNoAccessTokenKey(option: CredentialOption) {
	if (option.method.type !== "oauth" || typeof option.method.delivery !== "object") return;
	const { tokenResponseFields = [], callbackQueryFields = [] } = option.method;
	const keys = [...option.fields, ...tokenResponseFields, ...callbackQueryFields].map((field) => field.key);
	if (keys.includes(ACCESS_TOKEN_KEY)) {
		throw new Error(`Credential option "${option.id}" has a field named "${ACCESS_TOKEN_KEY}", which its OAuth access token already uses.`);
	}
}

type KeySet = ReturnType<typeof createRemoteJWKSet>;

type WildcardIssuer = { protocol: string; port: string; suffix: string; jwksPath: string };

/** Bounds the key sets kept for wildcard matches, since a caller can claim any subdomain. */
const MAX_WILDCARD_KEY_SETS = 256;

function wildcardIssuer({ issuer, jwksUrl }: TrustedIssuer): WildcardIssuer | undefined {
	if (!issuer.includes("://*.")) return undefined;
	const base = issuer.replace("://*.", "://");
	const url = URL.canParse(base) ? new URL(base) : undefined;
	if (url?.origin !== base) throw new Error(`Futurity issuer "${issuer}" must be an origin such as "https://*.futurity.work".`);
	if (!jwksUrl.startsWith("/")) throw new Error(`Futurity issuer "${issuer}" needs a jwksUrl path such as "/oauth/jwks".`);
	return { protocol: url.protocol, port: url.port, suffix: `.${url.hostname}`, jwksPath: jwksUrl };
}

function matchesWildcard(wildcard: WildcardIssuer, issuer: string): boolean {
	if (!URL.canParse(issuer)) return false;
	const url = new URL(issuer);
	return (
		url.origin === issuer &&
		url.protocol === wildcard.protocol &&
		url.port === wildcard.port &&
		url.hostname.length > wildcard.suffix.length &&
		url.hostname.endsWith(wildcard.suffix)
	);
}

/** Resolves a claimed `iss` to the key set that may verify it, or undefined when no trusted issuer covers it. */
function trustedKeySets(issuers: TrustedIssuer[]): (issuer: string) => KeySet | undefined {
	if (issuers.length === 0) throw new Error("futurity.issuers needs at least one trusted issuer.");
	const exact = new Map<string, KeySet>();
	const wildcards: WildcardIssuer[] = [];
	const listed = new Set<string>();
	for (const trusted of issuers) {
		if (listed.has(trusted.issuer)) throw new Error(`Futurity issuer "${trusted.issuer}" is listed twice.`);
		listed.add(trusted.issuer);
		const wildcard = wildcardIssuer(trusted);
		if (wildcard) wildcards.push(wildcard);
		else exact.set(trusted.issuer, createRemoteJWKSet(new URL(trusted.jwksUrl)));
	}

	const matched = new Map<string, KeySet>();
	return (issuer) => {
		const known = exact.get(issuer) ?? matched.get(issuer);
		if (known) return known;
		const wildcard = wildcards.find((candidate) => matchesWildcard(candidate, issuer));
		if (!wildcard) return undefined;
		if (matched.size >= MAX_WILDCARD_KEY_SETS) matched.clear();
		const keySet = createRemoteJWKSet(new URL(wildcard.jwksPath, issuer));
		matched.set(issuer, keySet);
		return keySet;
	};
}

/** The token's unverified `iss`, used only to pick which trusted key set verifies it. */
function claimedIssuer(token: string): string | undefined {
	try {
		const { iss } = decodeJwt(token);
		return typeof iss === "string" ? iss : undefined;
	} catch {
		return undefined;
	}
}

/**
 * Verifies the Futurity identity token on a request and collects its credentials.
 * Futurity sets `aud` to the manifest's remote URL exactly as written, so the request's Host never decides it.
 */
export function identityVerifier(manifest: PluginManifest, options: FuturityOptions) {
	const keySetFor = trustedKeySets(options.issuers);
	const audience = manifest.remotes[0].url;
	const credentialOptions = new Map(futurityExtension(manifest).credentials.map((option) => [option.id, option]));
	for (const option of credentialOptions.values()) assertNoAccessTokenKey(option);

	return async (req: Request): Promise<VerifiedRequest | Response> => {
		const token = bearerToken(req);
		if (!token) return errorResponse(401, "unauthorized", "Missing Futurity identity token in Authorization");

		const issuer = claimedIssuer(token);
		const jwks = issuer === undefined ? undefined : keySetFor(issuer);
		if (issuer === undefined || jwks === undefined) {
			return errorResponse(401, "unauthorized", "Futurity identity token is not from a trusted issuer");
		}

		let payload: unknown;
		try {
			({ payload } = await jwtVerify(token, jwks, { issuer, audience }));
		} catch (error) {
			return errorResponse(401, "unauthorized", `Invalid Futurity identity token: ${(error as Error).message}`);
		}

		const claims = FuturityIdentityClaimsSchema.safeParse(payload);
		if (!claims.success) {
			const paths = claims.error.issues.map((issue) => issue.path.join(".")).join(", ");
			return errorResponse(401, "unauthorized", `Futurity identity token has malformed claims: ${paths}`);
		}
		const option = credentialOptions.get(claims.data.credential_option);
		if (!option) {
			return errorResponse(401, "unauthorized", `Credential option "${claims.data.credential_option}" is not declared by this plugin`);
		}
		if (option.holder !== claims.data.holder) {
			return errorResponse(401, "unauthorized", `Credential option "${option.id}" is held by "${option.holder}", not "${claims.data.holder}"`);
		}

		const delivered = readCredentials(req, option);
		if ("missing" in delivered) {
			return errorResponse(400, "missing_credential", `Missing credential header ${delivered.missing}`);
		}

		return {
			identity: {
				issuer,
				org: { id: claims.data.org_id },
				user: { id: claims.data.sub },
				holder: claims.data.holder,
				credentials: delivered.credentials,
			},
			token,
			expiresAt: claims.data.exp,
		};
	};
}
