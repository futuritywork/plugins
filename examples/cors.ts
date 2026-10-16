import { z } from "zod";
import { mcp } from "@futurity/plugins";
import { cors } from "@futurity/plugins/cors";

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) throw new Error("Set FUTURITY_SIGNING_KEY to an Ed25519 PKCS8 DER base64 private key");

const app = mcp({
	catalog: { grant_type: "none" },
	pluginManifest: {
		specVersion: 3,
		pluginId: "my-cors-server",
		name: "CORS Example",
		version: "1.0.0",
		mcpUrl: "http://localhost:3000/mcp",
		auth: { type: "none" },
		signingKey,
	},
	name: "my-cors-server",
	version: "1.0.0",
	path: "/mcp",
});

app.use(
	cors({
		allowOrigin: "*",
		allowMethods: ["GET", "POST", "OPTIONS"],
	})
);

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
