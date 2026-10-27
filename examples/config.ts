// Shared signing and public URL configuration for the local examples.
const key = process.env.FUTURITY_SIGNING_KEY;
if (!key) {
	throw new Error(
		"FUTURITY_SIGNING_KEY is required. Generate an Ed25519 keypair (see README.md) and set the private key before running this example."
	);
}

export const signingKey = key;
export const mcpUrl = `${process.env.PUBLIC_URL ?? "http://localhost:3000"}/mcp`;
