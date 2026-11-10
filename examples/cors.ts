import { z } from "zod";
import { mcp } from "@futurity/plugins";
import { exampleManifest, examplePort } from "./config";
import { cors } from "@futurity/plugins/cors";


const app = mcp({
	manifest: exampleManifest("my-cors-server", "CORS Example", "Says hello from behind a CORS policy"),
	futurity: false,
	path: "/mcp",
});

app.use(
	cors({
		origins: ["https://app.futurity.work", "http://localhost:5173"],
		allowMethods: ["GET", "POST", "OPTIONS"],
	})
);

app.tool("hello", {
	description: "Say hello",
	annotations: { readOnlyHint: true },
	input: z.object({
		name: z.string(),
	}),
	output: z.object({ greeting: z.string() }),
	handler: async ({ name }) => {
		return { greeting: `Hello, ${name}!` };
	},
});

app.listen(examplePort);
