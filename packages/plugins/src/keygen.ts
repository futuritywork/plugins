import { generateKeyPair } from "./signing";

const { privateKey, publicKey } = generateKeyPair();

console.log("Ed25519 Keypair Generated\n");
console.log("Private key (PKCS8 DER, base64) — keep secret:");
console.log(`FUTURITY_SIGNING_KEY=${privateKey}`);
console.log("\nPublic key (SPKI DER, base64) — register with Futurity API:");
console.log(publicKey);
