import {
	parsePluginManifest,
	type PluginManifest,
	type PluginManifestInput,
} from "@futurity/plugin-manifest";
import type { ServerOptions } from "@modelcontextprotocol/sdk/server/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
	ListToolsRequestSchema,
	type Implementation,
	type Tool,
	type ToolAnnotations,
} from "@modelcontextprotocol/sdk/types.js";
import type { JsonSchemaType, JsonSchemaValidator } from "@modelcontextprotocol/sdk/validation";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/ajv";
import { z } from "zod";
import { identityVerifier, type FuturityIdentity, type FuturityOptions } from "./identity";
import {
	StreamableHttpServer,
	StreamableHttpTransport,
	type Authenticated,
} from "./transports/streamableHttp";
import { WebSocketTransport } from "./transports/websocket";
import type { Middleware } from "./types";

/** The context of an app built with `futurity: false`, where no caller is verified. */
export type NoIdentity = {
	issuer: null;
	org: null;
	user: null;
	holder: null;
	credentials: Record<string, never>;
};

const NO_IDENTITY: NoIdentity = { issuer: null, org: null, user: null, holder: null, credentials: {} };

type Identity = FuturityIdentity | NoIdentity;

/** Per-call context supplied to tool handlers. */
export type ToolContext<I extends Identity = FuturityIdentity> = I & {
	/** Aborted on MCP request cancellation or connection closure. Pass to downstream I/O to stop work cooperatively. */
	signal: AbortSignal;
};

export interface ToolOptions<I, O, C extends Identity = FuturityIdentity> {
	description?: string;
	input?: z.ZodType<I>;
	/** Declares the final handler result: an object or a union of objects, advertised as the tool's outputSchema. Registering a tool throws on any schema that cannot be advertised. */
	output: z.ZodType<O>;
	/** Standard MCP tool annotations, sent to clients unchanged. Futurity reads danger from readOnlyHint and destructiveHint. */
	annotations?: ToolAnnotations;
	/** The input schema one connection's tools/list advertises, e.g. naming that tenant's values; calls still parse with `input`. */
	listedInput?: (schema: InputJsonSchema, context: ToolContext<C>) => Promise<InputJsonSchema> | InputJsonSchema;
	handler: (input: I, context: ToolContext<C>) => Promise<O> | O;
}

export interface ResourceOptions<T, C extends Identity = FuturityIdentity> {
	description?: string;
	fetch: (context: ToolContext<C>) => Promise<T> | T;
}

export interface McpAppOptions {
	/** The spec 5 manifest, validated at construction and served at `/.well-known/futurity/plugin`. */
	manifest: PluginManifestInput;
	instructions?: ServerOptions["instructions"];
	/** Verifies the Futurity identity token on every MCP request; `false` serves without identity. */
	futurity: FuturityOptions | false;
	capabilities?: ServerOptions["capabilities"];
	path?: string;
	middleware?: Middleware[];
}

export type InputJsonSchema = Tool["inputSchema"];
type OutputJsonSchema = NonNullable<Tool["outputSchema"]>;

const EMPTY_INPUT: InputJsonSchema = { type: "object", properties: {} };

/** MCP requires an object at the root, so a union of objects is advertised as an object constrained by anyOf. */
function inputJsonSchema(name: string, schema: z.ZodType<unknown> | undefined): InputJsonSchema {
	if (!schema) return EMPTY_INPUT;
	const json = z.toJSONSchema(schema, { target: "draft-7", io: "input" });
	if (json.type !== undefined && json.type !== "object") {
		throw new Error(`Tool ${name} input must be an object schema, not ${String(json.type)}`);
	}
	return { ...json, type: "object" } as InputJsonSchema;
}

/** A key whose parsed value may be undefined is absent from the JSON a client receives. */
function mayBeAbsent(schema: z.ZodType<unknown>): boolean {
	try {
		const result = schema.safeParse(undefined);
		return result.success && result.data === undefined;
	} catch {
		return false;
	}
}

type OutputContract = {
	jsonSchema: OutputJsonSchema;
	// compiled on the tool's first call, so a gateway of many tools pays only for the ones it serves
	validate?: JsonSchemaValidator<unknown>;
};

/** AJV compiles patterns as unicode regular expressions, so each one must compile that way. */
function assertPatternsCompile(schema: unknown): void {
	if (Array.isArray(schema)) return schema.forEach(assertPatternsCompile);
	if (typeof schema !== "object" || schema === null) return;
	for (const [key, value] of Object.entries(schema)) {
		if (key === "pattern" && typeof value === "string") new RegExp(value, "u");
		else assertPatternsCompile(value);
	}
}

function isObjectShaped(schema: z.ZodType<unknown>): boolean {
	const def = schema._zod.def;
	if (def.type === "object") return true;
	return def.type === "union" && (def as unknown as { options: z.ZodType<unknown>[] }).options.every(isObjectShaped);
}

/** Compiles the client's output contract; MCP requires an object at the root, so a union of objects is advertised as an object constrained by anyOf. */
function compileOutputContract(name: string, schema: z.ZodType<unknown>): OutputContract {
	if (!schema) throw new Error(`Tool ${name} must declare an output schema`);
	if (!isObjectShaped(schema)) {
		throw new Error(`Tool ${name} output must be an object schema or a union of objects, not ${schema._zod.def.type}`);
	}
	try {
		const json = z.toJSONSchema(schema, {
			target: "draft-7",
			io: "output",
			unrepresentable: "throw",
			override: ({ zodSchema, jsonSchema }) => {
				// MCP re-parses normalized results, so a rewritten result would no longer match the advertised schema.
				const def = zodSchema._zod.def;
				if (def.type === "pipe" || def.checks?.some(check => check._zod.def.check === "overwrite")) {
					throw new Error("transforms, pipelines and overwrites cannot be advertised");
				}
				if (def.type === "object" && jsonSchema.required) {
					const shape = (def as unknown as { shape: Record<string, z.ZodType<unknown>> }).shape;
					jsonSchema.required = jsonSchema.required.filter((key) => !mayBeAbsent(shape[key]!));
					if (jsonSchema.required.length === 0) delete jsonSchema.required;
				}
			},
		});
		assertPatternsCompile(json);
		return { jsonSchema: { ...json, type: "object" } as OutputJsonSchema };
	} catch (cause) {
		throw new Error(`Tool ${name} output cannot be advertised: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
	}
}

/** A tool result that missed its declared output; the shape matches the marketplace's vendor schema reports. */
export type OutputViolationReport = {
	caller: string;
	schema: string;
	issues: string;
	timestamp: string;
};

type OutputViolationHandler = (report: OutputViolationReport) => void | Promise<void>;

let onOutputViolation: OutputViolationHandler = (report) => {
	console.warn(`[output-violation] ${report.schema} ${report.caller}`, report);
};

/** Receives every tool result that misses its declared output; the call still returns that result. */
export function setOutputViolationHandler(handler: OutputViolationHandler): void {
	onOutputViolation = handler;
}

const ISSUES_CHARS = 2000;

// a report names paths and issue codes, never a value from the result, since results carry customer data
function reportOutputViolation(plugin: string, tool: string, issues: string): void {
	const report: OutputViolationReport = {
		caller: tool,
		schema: `${plugin} output`,
		issues: issues.slice(0, ISSUES_CHARS),
		timestamp: new Date().toISOString(),
	};
	// a reporter that throws or rejects never reaches the call
	Promise.resolve(report).then(onOutputViolation).catch(() => {});
}

/** Clients receive JSON, so the JSON form is what is checked and sent. */
function jsonForm(value: unknown): unknown {
	try {
		return JSON.parse(JSON.stringify(value) ?? "null");
	} catch {
		return "(the result has no JSON form)";
	}
}

function issueLines(issues: z.core.$ZodIssue[]): string {
	return issues.slice(0, 15).map((issue) => `${issue.path.map(String).join(".") || "(root)"}: ${issue.message} (${issue.code})`).join("\n");
}

/** A result that misses the contract comes back as produced, with what it missed. */
async function checkOutput(schema: z.ZodType<unknown>, contract: OutputContract, result: unknown): Promise<{ json: unknown; issues: string | null }> {
	try {
		const parsed = await schema.safeParseAsync(result);
		if (!parsed.success) return { json: jsonForm(result), issues: issueLines(parsed.error.issues) };
		const json = jsonForm(parsed.data);
		// Zod and the SDK use different JSON Schema typings; AJV checks the contract a client receives.
		contract.validate ??= new AjvJsonSchemaValidator().getValidator(contract.jsonSchema as JsonSchemaType);
		const validation = contract.validate(json);
		return { json, issues: validation.valid ? null : `JSON Schema: ${validation.errorMessage}` };
	} catch (cause) {
		return { json: jsonForm(result), issues: `the output check threw: ${cause instanceof Error ? cause.message : String(cause)}` };
	}
}

/** MCP structuredContent must be a JSON object, so any other result travels as text alone. */
function toolAnswer(json: unknown) {
	const text = typeof json === "string" ? json : JSON.stringify(json);
	const isObject = typeof json === "object" && json !== null && !Array.isArray(json);
	return {
		content: [{ type: "text" as const, text }],
		...(isObject && { structuredContent: json as Record<string, unknown> }),
	};
}

type ToolRegistration = {
	name: string;
	opts: ToolOptions<unknown, unknown, Identity>;
	inputSchema: InputJsonSchema;
	output: OutputContract;
};

type ResourceRegistration = {
	name: string;
	opts: ResourceOptions<unknown, Identity>;
};

type RequestExtra = { authInfo?: { extra?: { identity?: unknown } }; signal: AbortSignal };

function contextOf(extra: RequestExtra): ToolContext<Identity> {
	const identity = (extra.authInfo?.extra?.identity as FuturityIdentity | undefined) ?? NO_IDENTITY;
	return { ...identity, signal: extra.signal };
}

/** Localhost http remotes pass here; the platform applies the production URL rules when it fetches. */
function validManifest(input: PluginManifestInput): PluginManifest {
	const result = parsePluginManifest(input, { development: true });
	if (!result.success) {
		throw new Error(`Invalid plugin manifest:\n${result.errors.map((error) => `  ${error}`).join("\n")}`);
	}
	return result.manifest;
}

export class McpApp<C extends Identity = FuturityIdentity> {
	readonly manifest: PluginManifest;
	private authenticate?: (req: Request) => Promise<Authenticated | Response>;
	private toolRegistrations: ToolRegistration[] = [];
	private resourceRegistrations: ResourceRegistration[] = [];
	private middlewares: Middleware[] = [];
	private httpServer?: StreamableHttpServer;
	private sessions = new Map<string, McpServer>();
	private _httpHandler?: (req: Request) => Promise<Response>;
	private _wsTransport?: WebSocketTransport;
	private _bunServer?: ReturnType<typeof Bun.serve>;

	/** Throws when the manifest breaks a spec 5 rule. */
	constructor(private options: McpAppOptions) {
		this.manifest = validManifest(options.manifest);
		if (options.futurity) {
			const verify = identityVerifier(this.manifest, options.futurity);
			this.authenticate = async (req) => {
				const verified = await verify(req);
				if (verified instanceof Response) return verified;
				const { identity, token, expiresAt } = verified;
				return {
					authInfo: { token, clientId: identity.issuer, scopes: [], expiresAt, extra: { identity } },
					principal: JSON.stringify([identity.issuer, identity.org.id, identity.user.id]),
				};
			};
		}
		if (options.middleware) {
			this.middlewares.push(...options.middleware);
		}
	}

	private createServer(): McpServer {
		const { name, title, description, version, icons, websiteUrl } = this.manifest;
		const serverInfo: Implementation = { name, title, description, version, icons, websiteUrl };
		const serverOptions: ServerOptions = {
			capabilities: this.options.capabilities,
			instructions: this.options.instructions,
		};
		const server = new McpServer(serverInfo, serverOptions);

		// The SDK parses arguments with the whole input schema; outputs are checked here against the advertised contract.
		for (const { name, opts, output } of this.toolRegistrations) {
			server.registerTool(
				name,
				{
					description: opts.description,
					inputSchema: opts.input,
					...(opts.annotations && { annotations: opts.annotations }),
				},
				async (input: any, extra: any) => {
					// The SDK passes context as the first argument for tools without an input schema.
					const context = contextOf(opts.input ? extra : input);
					const result = await opts.handler(opts.input ? input : {}, context);
					const { json, issues } = await checkOutput(opts.output, output, result);
					if (issues) reportOutputViolation(this.manifest.name, name, issues);
					return toolAnswer(json);
				}
			);
		}

		// McpServer advertises only object inputs and its own output conversion, so list the schemas validated here.
		if (this.toolRegistrations.length > 0) {
			// one tool at a time, so tools whose listed input reads the same upstream share its cached answer
			server.server.setRequestHandler(ListToolsRequestSchema, async (_request, extra) => {
				const tools: Tool[] = [];
				for (const { name, opts, inputSchema, output } of this.toolRegistrations) {
					tools.push({
						name,
						description: opts.description,
						inputSchema: opts.listedInput ? await opts.listedInput(inputSchema, contextOf(extra)) : inputSchema,
						outputSchema: output.jsonSchema,
						...(opts.annotations && { annotations: opts.annotations }),
					});
				}
				return { tools };
			});
		}

		// Register all resources
		for (const { name, opts } of this.resourceRegistrations) {
			server.registerResource(
				name,
				name,
				{ description: opts.description },
				async (uri, extra) => {
					const result = await opts.fetch(contextOf(extra));
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

	tool<I, O>(name: string, opts: ToolOptions<I, O, C>) {
		this.toolRegistrations.push({
			name,
			opts: opts as ToolOptions<unknown, unknown, Identity>,
			inputSchema: inputJsonSchema(name, opts.input),
			output: compileOutputContract(name, opts.output),
		});
		return this;
	}

	resource<T>(name: string, opts: ResourceOptions<T, C>) {
		this.resourceRegistrations.push({
			name,
			opts: opts as ResourceOptions<unknown, Identity>,
		});
		return this;
	}

	use(plugin: (app: this) => void | Promise<void>) {
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

	private wellKnown(): Record<string, unknown> {
		return { "futurity/plugin": this.manifest };
	}

	private buildHttpHandler(): (req: Request) => Promise<Response> {
		const path = this.options.path ?? "/mcp";
		this.httpServer = new StreamableHttpServer({
			path,
			wellKnown: this.wellKnown(),
			authenticate: this.authenticate,
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
				return this.httpServer!.handleFetch(req);
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
			if (this.options.futurity) {
				throw new Error("The WebSocket transport carries no Futurity identity; use HTTP, or build the app with futurity: false.");
			}
			const path = this.options.path ?? "/mcp";
			const wellKnown = this.wellKnown();

			// WebSocket: single server, single transport (for now)
			const server = this.createServer();
			this._wsTransport = new WebSocketTransport({
				port,
				path,
				wellKnown,
				middleware: this.middlewares,
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

export function mcp(options: McpAppOptions & { futurity: FuturityOptions }): McpApp<FuturityIdentity>;
export function mcp(options: McpAppOptions & { futurity: false }): McpApp<NoIdentity>;
export function mcp(options: McpAppOptions): McpApp<Identity> {
	return new McpApp(options);
}
