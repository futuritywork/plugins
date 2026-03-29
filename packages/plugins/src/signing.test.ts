import { test, expect, describe } from "bun:test";
import { generateKeyPair, signPayload, verifyPayload } from "./signing";

describe("generateKeyPair", () => {
	test("returns base64-encoded private and public keys", () => {
		const { privateKey, publicKey } = generateKeyPair();
		expect(privateKey).toBeString();
		expect(publicKey).toBeString();
		// Base64 strings should be non-empty
		expect(privateKey.length).toBeGreaterThan(0);
		expect(publicKey.length).toBeGreaterThan(0);
		// Should be valid base64
		expect(() => Buffer.from(privateKey, "base64")).not.toThrow();
		expect(() => Buffer.from(publicKey, "base64")).not.toThrow();
	});

	test("generates distinct keypairs each time", () => {
		const a = generateKeyPair();
		const b = generateKeyPair();
		expect(a.privateKey).not.toBe(b.privateKey);
		expect(a.publicKey).not.toBe(b.publicKey);
	});
});

describe("signPayload / verifyPayload", () => {
	const { privateKey, publicKey } = generateKeyPair();
	const payload = JSON.stringify({ pluginId: "test", name: "Test Plugin" });

	test("sign produces a JWS detached content string", () => {
		const jws = signPayload(payload, privateKey);
		const parts = jws.split(".");
		expect(parts).toHaveLength(3);
		// Middle part (payload) must be empty for detached content
		expect(parts[1]).toBe("");
	});

	test("verify returns true for valid signature", () => {
		const jws = signPayload(payload, privateKey);
		expect(verifyPayload(payload, jws, publicKey)).toBe(true);
	});

	test("verify returns false for tampered payload", () => {
		const jws = signPayload(payload, privateKey);
		const tampered = payload + " tampered";
		expect(verifyPayload(tampered, jws, publicKey)).toBe(false);
	});

	test("verify returns false for wrong public key", () => {
		const jws = signPayload(payload, privateKey);
		const other = generateKeyPair();
		expect(verifyPayload(payload, jws, other.publicKey)).toBe(false);
	});

	test("verify returns false for malformed JWS", () => {
		expect(verifyPayload(payload, "not-a-jws", publicKey)).toBe(false);
		expect(verifyPayload(payload, "a.b.c", publicKey)).toBe(false);
		expect(verifyPayload(payload, "", publicKey)).toBe(false);
	});

	test("header contains alg=EdDSA and b64=false", () => {
		const jws = signPayload(payload, privateKey);
		const headerB64 = jws.split(".")[0]!;
		const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
		expect(header.alg).toBe("EdDSA");
		expect(header.b64).toBe(false);
		expect(header.crit).toContain("b64");
	});
});
