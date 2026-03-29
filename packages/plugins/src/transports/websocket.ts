import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { Server, ServerWebSocket } from "bun";
import type { AuthMiddleware, Middleware, WellKnownEntry } from "../types";

export interface WebSocketTransportOptions {
	port: number;
	path: string;
	wellKnown?: Record<string, WellKnownEntry>;
	auth?: AuthMiddleware;
	middleware?: Middleware[];
}

export class WebSocketTransport implements Transport {
	private server?: Server<unknown>;
	private socket?: ServerWebSocket<unknown>;

	onclose?: () => void;
	onerror?: (error: Error) => void;
	onmessage?: (message: JSONRPCMessage) => void;

	constructor(private opts: WebSocketTransportOptions) {}

	async start() {
		return new Promise<void>((resolve) => {
			this.server = Bun.serve({
				hostname: "0.0.0.0",
				port: this.opts.port,
				fetch: async (req, server) => {
					// Compose middlewares
					const runMiddlewares = async (
						index: number,
						req: Request
					): Promise<Response | undefined> => {
						if (this.opts.middleware && index < this.opts.middleware.length) {
							return this.opts.middleware[index]?.(req, (nextReq) =>
								runMiddlewares(index + 1, nextReq)
							);
						}
						return this.handleFetch(req, server);
					};

					const response = await runMiddlewares(0, req);
					// If response is undefined, it means connection was upgraded
					return response || new Response("Hello world!");
				},
				websocket: {
					open: (ws) => {
						this.socket = ws;
					},
					message: (ws, message) => {
						try {
							const msg = JSON.parse(message.toString());
							this.onmessage?.(msg);
						} catch (err) {
							console.error("Invalid MCP message:", err);
						}
					},
					close: (ws) => {
						this.onclose?.();
					},
				},
			});
			resolve();
		});
	}

	private async handleFetch(
		req: Request,
		server: Server<unknown>
	): Promise<Response | undefined> {
		const url = new URL(req.url);

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

		if (this.opts.auth) {
			try {
				const authorized = await this.opts.auth(req);
				if (!authorized) {
					return new Response("Unauthorized", { status: 401 });
				}
			} catch (err) {
				console.error("Auth error:", err);
				return new Response("Unauthorized", { status: 401 });
			}
		}

		if (url.pathname === this.opts.path) {
			const success = server.upgrade(req, {
				data: undefined,
			});
			if (success) {
				return undefined;
			}
		}

		return undefined;
	}

	async send(message: JSONRPCMessage) {
		if (this.socket) {
			this.socket.send(JSON.stringify(message));
		}
	}

	async close() {
		this.server?.stop();
		this.onclose?.();
	}
}
