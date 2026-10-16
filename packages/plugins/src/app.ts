import type { ServerOptions } from "@modelcontextprotocol/sdk/server/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type {
	Implementation,
	ToolAnnotations,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { createCatalogHandler, type CatalogOptions } from "./catalog";
import { createChainedAuthRouter } from "./chainedAuth";
import { OAuthOptionsSchema, type OAuthOptions } from "./oauth";
import {
	PluginManifestSchema,
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
	DangerLevel,
	Middleware,
	WellKnownEntry,
} from "./types";

function buildAnnotations(
	opts: ToolOptions<unknown, unknown>
): ToolAnnotations | undefined {
	if (!opts.dangerLevel && !opts.requiresExplicitConsent) return undefined;

	const level = opts.dangerLevel ?? "read";
	return {
		// Standard MCP annotation hints
		readOnlyHint: level === "read",
		destructiveHint: level === "delete",
	};
}

/** Per-call context supplied to tool handlers. */
export interface ToolContext {
	/** Aborted on MCP request cancellation or connection closure. Pass to downstream I/O to stop work cooperatively. */
	signal: AbortSignal;
}

export interface ToolOptions<I, O> {
	description?: string;
	input?: z.ZodType<I>;
	/** Advertises and parses final object results when JSON-Schema-representable and pipeline-free, applying defaults and object field rules to both response forms; otherwise retains text-only output. */
	output?: z.ZodType<O>;
	handler: (input: I, context: ToolContext) => Promise<O> | O;
	/** Tool danger level. Defaults to "read" if not specified. */
	dangerLevel?: DangerLevel;
	/** Whether this tool requires explicit user consent before execution, regardless of the user's permission mode. */
	requiresExplicitConsent?: boolean;
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
	/** Required signed manifest. Validated and snapshotted at construction, including its signing key. */
	pluginManifest: PluginManifestOptions;
	/** Required public GET /api/catalog metadata; identity comes from pluginManifest. Validated at construction. */
	catalog: CatalogOptions;
	auth?: AuthMiddleware;
	chainedAuth?: ChainedAuthConfig;
	path?: string;
	middleware?: Middleware[];
}

/** Whether MCP can advertise the schema and re-validate the handler's final object. */
function declaresOutput(schema: z.ZodType<unknown> | undefined): boolean {
	if (schema?._zod.def.type !== "object") return false;
	try {
		z.toJSONSchema(schema, {
			target: "draft-7",
			io: "output",
			unrepresentable: "throw",
			override: ({ zodSchema }) => {
				// Output conversion can hide a pipeline's input transforms, which MCP would run again.
				if (zodSchema._zod.def.type === "pipe") {
					throw new Error("Output pipelines require text-only results");
				}
			},
		});
		return true;
	} catch {
		return false;
	}
}

type ToolRegistration = {
	name: string;
	opts: ToolOptions<unknown, unknown>;
	structured: boolean;
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
	private _httpHandler?: (req: Request) => Promise<Response>;
	private _wsTransport?: WebSocketTransport;
	private _bunServer?: ReturnType<typeof Bun.serve>;
	private catalogHandler: (req: Request) => Response | undefined;
	private readonly signedManifest: WellKnownEntry;

	constructor(private options: McpAppOptions) {
		const manifest = PluginManifestSchema.parse(options.pluginManifest);
		const signingKey = options.pluginManifest.signingKey;
		if (typeof signingKey !== "string" || !signingKey.trim()) {
			throw new Error("pluginManifest.signingKey is required (Ed25519 PKCS8 DER base64)");
		}
		const payload = JSON.stringify(manifest);
		this.signedManifest = {
			// Detach open-ended probe args too, so input mutation cannot invalidate the signature.
			body: JSON.parse(payload),
			headers: { "X-Futurity-Signature": signPayload(payload, signingKey) },
		};
		this.catalogHandler = createCatalogHandler(options.catalog, manifest);
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
		for (const { name, opts, structured } of this.toolRegistrations) {
			const annotations = buildAnnotations(opts);
			const meta: Record<string, unknown> = {};
			if (opts.dangerLevel) meta["futurity:dangerLevel"] = opts.dangerLevel;
			if (opts.requiresExplicitConsent)
				meta["futurity:requiresExplicitConsent"] =
					opts.requiresExplicitConsent;

			server.registerTool(
				name,
				{
					description: opts.description,
					inputSchema: opts.input
						? (opts.input as any).shape || opts.input
						: undefined,
					...(structured && { outputSchema: opts.output }),
					...(annotations && { annotations }),
					...(Object.keys(meta).length > 0 && { _meta: meta }),
				},
				async (input: any, extra: ToolContext) => {
					// The SDK passes context as the first argument for tools without an input schema.
					const context = opts.input ? extra : input;
					let result = await opts.handler(input, { signal: context.signal });
					if (structured) {
						// MCP validates but discards parsed data; normalize both response forms here.
						const parsed = await opts.output!.safeParseAsync(result);
						if (!parsed.success) {
							throw new Error(`Output validation error: Invalid structured content for tool ${name}: ${parsed.error.message}`);
						}
						result = parsed.data;
					}
					return {
						content: [
							{
								type: "text" as const,
								text: JSON.stringify(result),
							},
						],
						...(structured && {
							structuredContent: result as Record<string, unknown>,
						}),
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
			structured: declaresOutput(opts.output),
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
	 * Fetch handler — the primary API for handling MCP requests.
	 * Use with Bun.serve(), Cloudflare Workers, or any Request/Response runtime.
	 *
	 * Note: WebSocket transport is not supported via fetch. Use listen() for WS.
	 */
	get fetch(): (req: Request) => Promise<Response> {
		if (!this._httpHandler) {
			this._httpHandler = this.buildHttpHandler();
		}
		return this._httpHandler;
	}

	private buildWellKnown(): Record<string, WellKnownEntry> {
		const wellKnown: Record<string, WellKnownEntry> = {
			"futurity/plugin": this.signedManifest,
		};

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

			wellKnown["oauth-authorization-server"] = { body: authServer };
		}

		return wellKnown;
	}

	private buildHttpHandler(): (req: Request) => Promise<Response> {
		const path = this.options.path ?? "/mcp";
		const wellKnown = this.buildWellKnown();
		const chainedAuthRouter = this.options.chainedAuth
			? createChainedAuthRouter(this.options.chainedAuth)
			: undefined;

		this.httpServer = new StreamableHttpServer({
			path,
			wellKnown,
			auth: this.options.auth,
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

		return async (req: Request): Promise<Response> => {
			const runMiddlewares = async (
				index: number,
				req: Request
			): Promise<Response | undefined> => {
				if (this.middlewares.length > 0 && index < this.middlewares.length) {
					return this.middlewares[index]?.(req, (nextReq) =>
						runMiddlewares(index + 1, nextReq)
					);
				}
				return this.catalogHandler(req) ?? this.httpServer!.handleFetch(req);
			};

			const response = await runMiddlewares(0, req);
			return response || new Response("Not Found", { status: 404 });
		};
	}

	/**
	 * Listen for connections
	 */
	async listen(port: number, transportType: "websocket" | "http" = "http") {
		if (transportType === "websocket") {
			console.warn(
				"⚠️  WebSocket transport requires Bun runtime. It will not work in other environments."
			);
			const path = this.options.path ?? "/mcp";
			const wellKnown = this.buildWellKnown();

			// WebSocket: single server, single transport (for now)
			const server = this.createServer();
			this._wsTransport = new WebSocketTransport({
				port,
				path,
				wellKnown,
				auth: this.options.auth,
				middleware: this.middlewares,
				publicHandler: this.catalogHandler,
			});
			await server.connect(this._wsTransport);
		} else {
			// HTTP: get or build the fetch handler, then serve it with Bun
			const handler = this.fetch;
			this._bunServer = Bun.serve({
				hostname: "0.0.0.0",
				port,
				fetch: handler,
			});
		}

		const path = this.options.path ?? "/mcp";
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
		this._bunServer?.stop();
		this._bunServer = undefined;
		await this.httpServer?.stop();
		this._wsTransport?.close();
		this.sessions.clear();
	}
}

export const mcp = (options: McpAppOptions) => new McpApp(options);
