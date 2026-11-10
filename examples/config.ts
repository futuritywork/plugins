import { FUTURITY_META_KEY, type PluginManifestInput } from "@futurity/plugins";

export const examplePort = Number(process.env.PORT ?? 3000);

// The local examples need no credentials, so they declare one option held by no one.
export function exampleManifest(slug: string, title: string, description: string): PluginManifestInput {
	return {
		name: `com.example/${slug}`,
		title,
		description,
		version: "1.0.0",
		remotes: [{ type: "streamable-http", url: `${process.env.PUBLIC_URL ?? `http://localhost:${examplePort}`}/mcp` }],
		_meta: {
			[FUTURITY_META_KEY]: {
				specVersion: 5,
				developer: { email: "developer@example.com" },
				credentials: [{ id: "public", label: "No credentials", holder: "none", method: { type: "none" }, fields: [] }],
			},
		},
	};
}
