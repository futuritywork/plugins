import type { ServerOptions } from "@modelcontextprotocol/sdk/server/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Implementation } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { createChainedAuthRouter } from "./chainedAuth";
import { OAuthOptionsSchema, type OAuthOptions } from "./oauth";
import {
	PluginManifestSchema,
	PluginManifestSchemaCompat,
	type PluginManifestOptions,
} from "./pluginManifest";
import { signPayload } from "./signing";
import {
	StreamableHttpServer,
	StreamableHttpTransport,
} from "./transports/streamableHttp";
import { WebSocketTransport } from "./transports/websocket";
import type {
	AuthMiddleware,
	ChainedAuthConfig,
	Middleware,
	WellKnownEntry,
} from "./types";

export interface ToolOptions<I, O> {
	description?: string;
	input?: z.ZodType<I>;
	output?: z.ZodType<O>;
	handler: (input: I) => Promise<O> | O;
}

export interface ResourceOptions<T> {
	description?: string;
	fetch: () => Promise<T> | T;
}

export interface McpAppOptions {
	name: string;
	version: string;
	capabilities?: ServerOptions["capabilities"];
	instructions?: ServerOptions["instructions"];
	oauth?: OAuthOptions;
	pluginManifest?: PluginManifestOptions;
	auth?: AuthMiddleware;
	chainedAuth?: ChainedAuthConfig;
	path?: string;
	middleware?: Middleware[];
}

type ToolRegistration = {
	name: string;
	opts: ToolOptions<unknown, unknown>;
};

type ResourceRegistration = {
	name: string;
	opts: ResourceOptions<unknown>;
};

export class McpApp {
	private toolRegistrations: ToolRegistration[] = [];
	private resourceRegistrations: ResourceRegistration[] = [];
	private middlewares: Middleware[] = [];
	private httpServer?: StreamableHttpServer;
	private sessions = new Map<string, McpServer>();

	constructor(
		private options: McpAppOptions = {
			name: "mcp-app",
			version: "0.1.0",
		}
	) {
		if (options.middleware) {
			this.middlewares.push(...options.middleware);
		}
	}

	private createServer(): McpServer {
		const serverInfo: Implementation = {
			name: this.options.name,
			version: this.options.version,
		};
		const serverOptions: ServerOptions = {
			capabilities: this.options.capabilities,
			instructions: this.options.instructions,
		};
		const server = new McpServer(serverInfo, serverOptions);

		// Register all tools
		for (const { name, opts } of this.toolRegistrations) {
			server.registerTool(
				name,
				{
					description: opts.description,
					inputSchema: opts.input
						? (opts.input as any).shape || opts.input
						: undefined,
				},
				async (input: any) => {
					const result = await opts.handler(input);
					return {
						content: [
							{
								type: "text" as const,
								text: JSON.stringify(result),
							},
						],
					};
				}
			);
		}

		// Register all resources
		for (const { name, opts } of this.resourceRegistrations) {
			server.registerResource(
				name,
				name,
				{ description: opts.description },
				async (uri) => {
					const result = await opts.fetch();
					return {
						contents: [
							{
								uri: uri.href,
								text: JSON.stringify(result),
							},
						],
					};
				}
			);
		}

		return server;
	}

	tool<I, O>(name: string, opts: ToolOptions<I, O>) {
		this.toolRegistrations.push({
			name,
			opts: opts as ToolOptions<unknown, unknown>,
		});
		return this;
	}

	resource<T>(name: string, opts: ResourceOptions<T>) {
		this.resourceRegistrations.push({
			name,
			opts: opts as ResourceOptions<unknown>,
		});
		return this;
	}

	use(plugin: (app: McpApp) => void | Promise<void>) {
		plugin(this);
		return this;
	}

	middleware(middleware: Middleware) {
		this.middlewares.push(middleware);
		return this;
	}

	/**
	 * Listen for connections
	 */
	async listen(port: number, transportType: "websocket" | "http" = "http") {
		const path = this.options.path ?? "/mcp";
		let wellKnown: Record<string, WellKnownEntry> | undefined;
		let chainedAuthRouter:
			| ReturnType<typeof createChainedAuthRouter>
			| undefined;

		if (this.options.oauth) {
			const oauth = OAuthOptionsSchema.parse(this.options.oauth);
			const authServer: Record<string, unknown> = {
				issuer: oauth.issuer,
				authorization_endpoint: oauth.authorizationEndpoint,
				token_endpoint: oauth.tokenEndpoint,
				scopes_supported: oauth.scopesSupported ?? [],
				response_types_supported: oauth.responseTypesSupported ?? ["code"],
				grant_types_supported: oauth.grantTypesSupported ?? [
					"authorization_code",
				],
			};
			// Only include optional fields if they have values
			if (oauth.jwksUri) authServer.jwks_uri = oauth.jwksUri;
			if (oauth.tokenEndpointAuthMethodsSupported) {
				authServer.token_endpoint_auth_methods_supported =
					oauth.tokenEndpointAuthMethodsSupported;
			}
			if (oauth.registrationEndpoint)
				authServer.registration_endpoint = oauth.registrationEndpoint;
			if (oauth.userInfoEndpoint)
				authServer.userinfo_endpoint = oauth.userInfoEndpoint;

			wellKnown = { "oauth-authorization-server": { body: authServer } };
		}

		if (this.options.pluginManifest) {
			const { signingKey, ...manifestData } = this.options.pluginManifest;
			// Use compat schema to support both v1 and v2 manifest formats
			const manifest = PluginManifestSchemaCompat.parse(manifestData);
			const payload = JSON.stringify(manifest);
			const jws = signPayload(payload, signingKey);

			wellKnown ??= {};
			wellKnown["futurity/plugin"] = {
				body: manifest,
				headers: { "X-Futurity-Signature": jws },
			};
		}

		if (this.options.chainedAuth) {
			chainedAuthRouter = createChainedAuthRouter(this.options.chainedAuth);
		}

		if (transportType === "websocket") {
			// WebSocket: single server, single transport (for now)
			const server = this.createServer();
			const transport = new WebSocketTransport({
				port,
				path,
				wellKnown,
				auth: this.options.auth,
				middleware: this.middlewares,
			});
			await server.connect(transport);
		} else {
			// HTTP: multi-session support
			this.httpServer = new StreamableHttpServer({
				port,
				path,
				wellKnown,
				auth: this.options.auth,
				middleware: this.middlewares,
				chainedAuthRouter,
				onSession: async (transport: StreamableHttpTransport) => {
					const server = this.createServer();
					this.sessions.set(transport.sessionId, server);
					await server.connect(transport);
				},
				onSessionClose: (sessionId: string) => {
					this.sessions.delete(sessionId);
				},
			});
			await this.httpServer.start();
		}

		console.log(
			`MCP server listening on ${transportType}://localhost:${port}${path}`
		);
		return this;
	}

	/**
	 * Get the number of active sessions (HTTP only)
	 */
	get activeSessions(): number {
		return this.sessions.size;
	}

	/**
	 * Stop the server
	 */
	async stop(): Promise<void> {
		await this.httpServer?.stop();
		this.sessions.clear();
	}
}

export const mcp = (options?: McpAppOptions) => new McpApp(options);
