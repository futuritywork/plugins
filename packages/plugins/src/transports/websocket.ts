import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { Server, ServerWebSocket } from "bun";
import type { Middleware } from "../types";

/** Carries no caller identity, so it serves only apps built with `futurity: false`. */
export interface WebSocketTransportOptions {
	port: number;
	path: string;
	/** JSON bodies served at `/.well-known/<key>`. */
	wellKnown?: Record<string, unknown>;
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
			const body = this.opts.wellKnown?.[key];
			if (body !== undefined) return Response.json(body);
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
