import { z } from "zod";
import { mcp } from "@futurity/plugins";

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) throw new Error("Set FUTURITY_SIGNING_KEY to an Ed25519 PKCS8 DER base64 private key");

const app = mcp({
	catalog: { grant_type: "authorization_code" },
	pluginManifest: {
		specVersion: 3,
		pluginId: "my-oauth-server",
		name: "OAuth Example",
		version: "1.0.0",
		mcpUrl: "http://localhost:3000/mcp",
		auth: {
			type: "forwarding",
			grantType: "authorization_code",
			authorizationEndpoint: "https://auth.example.com/oauth/authorize",
			tokenEndpoint: "https://auth.example.com/oauth/token",
			requiredScopes: ["openid", "profile", "email"],
			deliveryMethod: "header",
		},
		signingKey,
	},
	name: "my-oauth-server",
	version: "1.0.0",
	oauth: {
		issuer: "https://auth.example.com",
		authorizationEndpoint: "https://auth.example.com/oauth/authorize",
		tokenEndpoint: "https://auth.example.com/oauth/token",
		jwksUri: "https://auth.example.com/.well-known/jwks.json",
		scopesSupported: ["openid", "profile", "email"],
	},
});

app.tool("hello", {
	description: "Say hello",
	input: z.object({
		name: z.string(),
	}),
	handler: async ({ name }) => {
		return `Hello, ${name}!`;
	},
});

app.listen(3000);
