import { z } from "zod";
import { mcp } from "../src";
import { cors } from "../src/cors";

const app = mcp({
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
