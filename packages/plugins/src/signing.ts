import {
	generateKeyPairSync,
	createPrivateKey,
	createPublicKey,
	sign,
	verify,
} from "node:crypto";

/**
 * Generate an Ed25519 keypair.
 * Returns base64-encoded PKCS8 (private) and SPKI (public) DER keys.
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
		privateKeyEncoding: { type: "pkcs8", format: "der" },
		publicKeyEncoding: { type: "spki", format: "der" },
	});
	return {
		privateKey: Buffer.from(privateKey).toString("base64"),
		publicKey: Buffer.from(publicKey).toString("base64"),
	};
}

function base64url(buf: Buffer): string {
	return buf.toString("base64url");
}

function base64urlDecode(str: string): Buffer {
	return Buffer.from(str, "base64url");
}

/**
 * Sign a JSON payload using Ed25519 with JWS Detached Content format.
 * Returns a compact JWS string: `header..signature` (no payload section).
 */
export function signPayload(payload: string, privateKeyBase64: string): string {
	const header = { alg: "EdDSA", b64: false, crit: ["b64"] };
	const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
	const payloadBytes = Buffer.from(payload, "utf-8");

	const signingInput = Buffer.concat([
		Buffer.from(headerB64 + ".", "ascii"),
		payloadBytes,
	]);

	const key = createPrivateKey({
		key: Buffer.from(privateKeyBase64, "base64"),
		format: "der",
		type: "pkcs8",
	});

	const signature = sign(null, signingInput, key);
	const signatureB64 = base64url(signature);

	return `${headerB64}..${signatureB64}`;
}

/**
 * Verify a JWS Detached Content signature against a payload.
 * Expects `header..signature` format and the original payload string.
 */
export function verifyPayload(
	payload: string,
	jws: string,
	publicKeyBase64: string,
): boolean {
	const parts = jws.split(".");
	if (parts.length !== 3 || parts[1] !== "") {
		return false;
	}

	const headerB64 = parts[0]!;
	const signatureB64 = parts[2]!;

	let header: { alg?: string; b64?: boolean };
	try {
		header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
	} catch {
		return false;
	}

	if (header.alg !== "EdDSA" || header.b64 !== false) {
		return false;
	}

	const payloadBytes = Buffer.from(payload, "utf-8");
	const signingInput = Buffer.concat([
		Buffer.from(headerB64 + ".", "ascii"),
		payloadBytes,
	]);

	const key = createPublicKey({
		key: Buffer.from(publicKeyBase64, "base64"),
		format: "der",
		type: "spki",
	});

	const signature = base64urlDecode(signatureB64);

	return verify(null, signingInput, key, signature);
}
