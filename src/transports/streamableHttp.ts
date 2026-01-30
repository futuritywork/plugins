import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
	isInitializeRequest,
	isJSONRPCError,
	isJSONRPCRequest,
	isJSONRPCResponse,
	JSONRPCMessageSchema,
	type JSONRPCMessage,
	type RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "bun";
import type { AuthMiddleware, Middleware, WellKnownEntry } from "../types";

export interface StreamableHttpServerOptions {
	port: number;
	path: string;
	wellKnown?: Record<string, WellKnownEntry>;
	auth?: AuthMiddleware;
	middleware?: Middleware[];
	sessionIdGenerator?: () => string;
	enableJsonResponse?: boolean;
	/**
	 * Called when a new session is created. Use this to connect an MCP server to the transport.
	 */
	onSession: (transport: StreamableHttpTransport) => void | Promise<void>;
	/**
	 * Called when a session is closed.
	 */
	onSessionClose?: (sessionId: string) => void | Promise<void>;
}

interface SSEWriter {
	write: (data: string) => void;
	close: () => void;
	closed: boolean;
}

/**
 * Bun-native Streamable HTTP server for MCP.
 * Manages multiple concurrent sessions, each with its own transport.
 */
export class StreamableHttpServer {
	private server?: Server<unknown>;
	private sessions = new Map<string, StreamableHttpTransport>();

	constructor(private opts: StreamableHttpServerOptions) {
		this.opts.sessionIdGenerator ??= () => crypto.randomUUID();
	}

	async start(): Promise<void> {
		return new Promise<void>((resolve) => {
			this.server = Bun.serve({
				hostname: "0.0.0.0",
				port: this.opts.port,
				fetch: async (req) => {
					const runMiddlewares = async (
						index: number,
						req: Request
					): Promise<Response | undefined> => {
						if (this.opts.middleware && index < this.opts.middleware.length) {
							return this.opts.middleware[index]?.(req, (nextReq) =>
								runMiddlewares(index + 1, nextReq)
							);
						}
						return this.handleFetch(req);
					};

					const response = await runMiddlewares(0, req);
					return response || new Response("Not Found", { status: 404 });
				},
			});
			resolve();
		});
	}

	private async handleFetch(req: Request): Promise<Response | undefined> {
		const url = new URL(req.url);

		// Handle .well-known paths
		if (url.pathname.startsWith("/.well-known/")) {
			const key = url.pathname.replace("/.well-known/", "");
			if (key === "health-check") {
				return new Response("OK 200", { status: 200 });
			}
			const entry = this.opts.wellKnown?.[key];
			if (entry) {
				return new Response(JSON.stringify(entry.body), {
					headers: {
						"Content-Type": "application/json",
						...entry.headers,
					},
				});
			}
		}

		if (url.pathname !== this.opts.path) {
			return undefined;
		}

		// Auth middleware
		if (this.opts.auth) {
			try {
				const authorized = await this.opts.auth(req);
				if (!authorized) {
					return this.jsonRpcError(401, -32000, "Unauthorized");
				}
			} catch {
				return this.jsonRpcError(401, -32000, "Unauthorized");
			}
		}

		switch (req.method) {
			case "GET":
				return this.handleGetRequest(req);
			case "POST":
				return this.handlePostRequest(req);
			case "DELETE":
				return this.handleDeleteRequest(req);
			default:
				return new Response(
					JSON.stringify({
						jsonrpc: "2.0",
						error: { code: -32000, message: "Method not allowed" },
						id: null,
					}),
					{
						status: 405,
						headers: {
							Allow: "GET, POST, DELETE",
							"Content-Type": "application/json",
						},
					}
				);
		}
	}

	private handleGetRequest(req: Request): Response {
		const accept = req.headers.get("accept");
		if (!accept?.includes("text/event-stream")) {
			return this.jsonRpcError(
				406,
				-32000,
				"Not Acceptable: Client must accept text/event-stream"
			);
		}

		const sessionId = req.headers.get("mcp-session-id");
		if (!sessionId) {
			return this.jsonRpcError(
				400,
				-32000,
				"Bad Request: Mcp-Session-Id header is required"
			);
		}

		const transport = this.sessions.get(sessionId);
		if (!transport) {
			return this.jsonRpcError(404, -32001, "Session not found");
		}

		return transport.handleGetRequest();
	}

	private async handlePostRequest(req: Request): Promise<Response> {
		const accept = req.headers.get("accept");
		if (
			!accept?.includes("application/json") ||
			!accept.includes("text/event-stream")
		) {
			return this.jsonRpcError(
				406,
				-32000,
				"Not Acceptable: Client must accept both application/json and text/event-stream"
			);
		}

		const contentType = req.headers.get("content-type");
		if (!contentType?.includes("application/json")) {
			return this.jsonRpcError(
				415,
				-32000,
				"Unsupported Media Type: Content-Type must be application/json"
			);
		}

		let rawMessage: unknown;
		try {
			rawMessage = await req.json();
		} catch {
			return this.jsonRpcError(400, -32700, "Parse error");
		}

		let messages: JSONRPCMessage[];
		try {
			if (Array.isArray(rawMessage)) {
				messages = rawMessage.map((msg) => JSONRPCMessageSchema.parse(msg));
			} else {
				messages = [JSONRPCMessageSchema.parse(rawMessage)];
			}
		} catch (error) {
			return this.jsonRpcError(400, -32700, "Parse error", String(error));
		}

		const isInitializationRequest = messages.some(isInitializeRequest);
		const sessionId = req.headers.get("mcp-session-id");

		if (isInitializationRequest) {
			// New session
			if (messages.length > 1) {
				return this.jsonRpcError(
					400,
					-32600,
					"Invalid Request: Only one initialization request is allowed"
				);
			}

			const newSessionId = this.opts.sessionIdGenerator!();
			const transport = new StreamableHttpTransport(
				newSessionId,
				this.opts.enableJsonResponse ?? false,
				() => {
					this.sessions.delete(newSessionId);
					this.opts.onSessionClose?.(newSessionId);
				}
			);

			this.sessions.set(newSessionId, transport);

			// Connect the MCP server to this transport (this calls transport.start() internally)
			await this.opts.onSession(transport);

			return transport.handlePostRequest(messages);
		}

		// Existing session
		if (!sessionId) {
			return this.jsonRpcError(
				400,
				-32000,
				"Bad Request: Mcp-Session-Id header is required"
			);
		}

		const transport = this.sessions.get(sessionId);
		if (!transport) {
			return this.jsonRpcError(404, -32001, "Session not found");
		}

		return transport.handlePostRequest(messages);
	}

	private handleDeleteRequest(req: Request): Response {
		const sessionId = req.headers.get("mcp-session-id");
		if (!sessionId) {
			return this.jsonRpcError(
				400,
				-32000,
				"Bad Request: Mcp-Session-Id header is required"
			);
		}

		const transport = this.sessions.get(sessionId);
		if (!transport) {
			return this.jsonRpcError(404, -32001, "Session not found");
		}

		transport.close();
		return new Response(null, { status: 200 });
	}

	private jsonRpcError(
		status: number,
		code: number,
		message: string,
		data?: string
	): Response {
		return new Response(
			JSON.stringify({
				jsonrpc: "2.0",
				error: { code, message, ...(data && { data }) },
				id: null,
			}),
			{
				status,
				headers: { "Content-Type": "application/json" },
			}
		);
	}

	async stop(): Promise<void> {
		for (const transport of this.sessions.values()) {
			await transport.close();
		}
		this.sessions.clear();
		this.server?.stop();
	}

	getSession(sessionId: string): StreamableHttpTransport | undefined {
		return this.sessions.get(sessionId);
	}

	get activeSessions(): number {
		return this.sessions.size;
	}
}

/**
 * Per-session transport for MCP Streamable HTTP.
 * Each instance handles one client session.
 */
export class StreamableHttpTransport implements Transport {
	private _streamMapping = new Map<string, SSEWriter>();
	private _requestToStreamMapping = new Map<RequestId, string>();
	private _requestResponseMap = new Map<RequestId, JSONRPCMessage>();
	private readonly _standaloneSseStreamId = "_GET_stream";
	private _started = false;

	onclose?: () => void;
	onerror?: (error: Error) => void;
	onmessage?: (message: JSONRPCMessage) => void;

	constructor(
		public readonly sessionId: string,
		private enableJsonResponse: boolean,
		private onSessionClose: () => void
	) {}

	async start(): Promise<void> {
		if (this._started) {
			throw new Error("Transport already started");
		}
		this._started = true;
	}

	handleGetRequest(): Response {
		if (this._streamMapping.has(this._standaloneSseStreamId)) {
			return new Response(
				JSON.stringify({
					jsonrpc: "2.0",
					error: {
						code: -32000,
						message: "Conflict: Only one SSE stream is allowed per session",
					},
					id: null,
				}),
				{ status: 409, headers: { "Content-Type": "application/json" } }
			);
		}

		const { readable, writer } = this.createSSEStream();
		this._streamMapping.set(this._standaloneSseStreamId, writer);

		return new Response(readable, {
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache, no-transform",
				Connection: "keep-alive",
				"mcp-session-id": this.sessionId,
			},
		});
	}

	handlePostRequest(messages: JSONRPCMessage[]): Response | Promise<Response> {
		const hasRequests = messages.some(isJSONRPCRequest);

		if (!hasRequests) {
			for (const message of messages) {
				this.onmessage?.(message);
			}
			return new Response(null, { status: 202 });
		}

		const streamId = crypto.randomUUID();

		if (this.enableJsonResponse) {
			return this.handleJsonResponse(messages, streamId);
		}

		return this.handleSSEResponse(messages, streamId);
	}

	private handleJsonResponse(
		messages: JSONRPCMessage[],
		streamId: string
	): Promise<Response> {
		for (const message of messages) {
			if (isJSONRPCRequest(message)) {
				this._requestToStreamMapping.set(message.id, streamId);
			}
			this.onmessage?.(message);
		}

		return new Promise((resolve) => {
			const checkResponses = () => {
				const relatedIds = Array.from(this._requestToStreamMapping.entries())
					.filter(([_, sid]) => sid === streamId)
					.map(([id]) => id);

				const allReady = relatedIds.every((id) =>
					this._requestResponseMap.has(id)
				);

				if (allReady) {
					clearInterval(interval);
					clearTimeout(timeout);

					const responses = relatedIds.map((id) =>
						this._requestResponseMap.get(id)
					);

					for (const id of relatedIds) {
						this._requestResponseMap.delete(id);
						this._requestToStreamMapping.delete(id);
					}

					const body =
						responses.length === 1
							? JSON.stringify(responses[0])
							: JSON.stringify(responses);

					resolve(
						new Response(body, {
							headers: {
								"Content-Type": "application/json",
								"mcp-session-id": this.sessionId,
							},
						})
					);
				}
			};

			const interval = setInterval(checkResponses, 10);
			const timeout = setTimeout(() => {
				clearInterval(interval);
				resolve(
					new Response(
						JSON.stringify({
							jsonrpc: "2.0",
							error: { code: -32603, message: "Response timeout" },
							id: null,
						}),
						{ status: 500, headers: { "Content-Type": "application/json" } }
					)
				);
			}, 30000);
		});
	}

	private handleSSEResponse(
		messages: JSONRPCMessage[],
		streamId: string
	): Response {
		const { readable, writer } = this.createSSEStream();
		this._streamMapping.set(streamId, writer);

		for (const message of messages) {
			if (isJSONRPCRequest(message)) {
				this._requestToStreamMapping.set(message.id, streamId);
			}
			this.onmessage?.(message);
		}

		return new Response(readable, {
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache",
				Connection: "keep-alive",
				"mcp-session-id": this.sessionId,
			},
		});
	}

	private createSSEStream(): { readable: ReadableStream; writer: SSEWriter } {
		let controller: ReadableStreamDefaultController<Uint8Array>;
		const encoder = new TextEncoder();

		const writer: SSEWriter = {
			closed: false,
			write: (data: string) => {
				if (!writer.closed) {
					try {
						controller.enqueue(encoder.encode(data));
					} catch {
						writer.closed = true;
					}
				}
			},
			close: () => {
				if (!writer.closed) {
					writer.closed = true;
					try {
						controller.close();
					} catch {
						// Already closed
					}
				}
			},
		};

		const readable = new ReadableStream<Uint8Array>({
			start: (ctrl) => {
				controller = ctrl;
			},
			cancel: () => {
				writer.closed = true;
			},
		});

		return { readable, writer };
	}

	private writeSSEEvent(writer: SSEWriter, message: JSONRPCMessage): boolean {
		if (writer.closed) return false;
		try {
			writer.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
			return true;
		} catch {
			return false;
		}
	}

	async send(message: JSONRPCMessage): Promise<void> {
		let requestId: RequestId | undefined;

		if (isJSONRPCResponse(message) || isJSONRPCError(message)) {
			requestId = message.id;
		}

		// Standalone SSE stream (notifications without a related request)
		if (requestId === undefined) {
			const writer = this._streamMapping.get(this._standaloneSseStreamId);
			if (writer) {
				this.writeSSEEvent(writer, message);
			}
			return;
		}

		const streamId = this._requestToStreamMapping.get(requestId);
		if (!streamId) {
			this.onerror?.(
				new Error(
					`No connection established for request ID: ${String(requestId)}`
				)
			);
			return;
		}

		const writer = this._streamMapping.get(streamId);

		if (this.enableJsonResponse) {
			this._requestResponseMap.set(requestId, message);
		} else if (writer) {
			this.writeSSEEvent(writer, message);
		}

		if (isJSONRPCResponse(message) || isJSONRPCError(message)) {
			this._requestResponseMap.set(requestId, message);

			const relatedIds = Array.from(this._requestToStreamMapping.entries())
				.filter(([_, sid]) => sid === streamId)
				.map(([id]) => id);

			const allResponsesReady = relatedIds.every((id) =>
				this._requestResponseMap.has(id)
			);

			if (allResponsesReady && writer) {
				writer.close();
				this._streamMapping.delete(streamId);

				for (const id of relatedIds) {
					this._requestResponseMap.delete(id);
					this._requestToStreamMapping.delete(id);
				}
			}
		}
	}

	async close(): Promise<void> {
		for (const writer of this._streamMapping.values()) {
			writer.close();
		}
		this._streamMapping.clear();
		this._requestToStreamMapping.clear();
		this._requestResponseMap.clear();
		this.onSessionClose();
		this.onclose?.();
	}
}

// Legacy export for backward compatibility
export { StreamableHttpServer as StreamableHttpTransport_v1 };
