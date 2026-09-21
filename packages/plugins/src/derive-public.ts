import { createPrivateKey, createPublicKey } from "node:crypto";

const privateKeyBase64 = process.argv[2];
if (!privateKeyBase64) {
	console.error("Usage: bun run derive-public <private-key-base64>");
	process.exit(1);
}

const privateKey = createPrivateKey({
	key: Buffer.from(privateKeyBase64, "base64"),
	format: "der",
	type: "pkcs8",
});

const publicKey = createPublicKey(privateKey);
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
const publicKeyBase64 = Buffer.from(publicKeyDer).toString("base64");

console.log(publicKeyBase64);
