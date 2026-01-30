import { z } from "zod";
import { mcp } from "../src";

const app = mcp({
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
