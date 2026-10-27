import { z } from "zod";
import { mcp } from "@futurity/plugins";
import { signingKey, mcpUrl } from "./config";
import { cors } from "@futurity/plugins/cors";

const app = mcp({
	name: "my-cors-server",
	version: "1.0.0",
	pluginManifest: {
		pluginId: "my-cors-server",
		developerEmail: "developer@example.com",
		name: "my-cors-server",
		version: "1.0.0",
		mcpUrl,
		auth: { type: "none" },
		signingKey,
	},
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
