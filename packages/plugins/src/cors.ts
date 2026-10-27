import type { McpApp } from "./app";
import type { Middleware } from "./types";

export interface CorsOptions {
	allowOrigin?: string | ((origin: string | null) => string | null);
	allowMethods?: string[];
	allowHeaders?: string[];
	exposeHeaders?: string[];
	maxAge?: number;
	credentials?: boolean;
}

export const cors = (options: CorsOptions = {}) => {
	const allowOrigin = options.allowOrigin ?? "*";
	const allowMethods = (
		options.allowMethods ?? ["GET", "POST", "DELETE", "OPTIONS"]
	).join(", ");
	const allowHeaders = (
		options.allowHeaders ?? [
			"Content-Type",
			"Authorization",
			"Accept",
			"Mcp-Session-Id",
			"Mcp-Protocol-Version",
		]
	).join(", ");
	const exposeHeaders = (
		options.exposeHeaders ?? ["Mcp-Session-Id"]
	).join(", ");
	const maxAge = (options.maxAge ?? 86400).toString();
	const credentials = options.credentials ?? false;

	const getOrigin = (req: Request): string => {
		const origin = req.headers.get("origin");
		if (typeof allowOrigin === "function") {
			return allowOrigin(origin) ?? "";
		}
		return allowOrigin;
	};

	const getCorsHeaders = (req: Request): Record<string, string> => {
		const origin = getOrigin(req);
		const headers: Record<string, string> = {
			"Access-Control-Allow-Origin": origin,
			"Access-Control-Allow-Methods": allowMethods,
			"Access-Control-Allow-Headers": allowHeaders,
			"Access-Control-Expose-Headers": exposeHeaders,
			"Access-Control-Max-Age": maxAge,
		};
		if (credentials) {
			headers["Access-Control-Allow-Credentials"] = "true";
		}
		return headers;
	};

	return (app: McpApp) => {
		const middleware: Middleware = async (req, next) => {
			const corsHeaders = getCorsHeaders(req);

			// Handle preflight OPTIONS request
			if (req.method === "OPTIONS") {
				return new Response(null, {
					status: 204,
					headers: corsHeaders,
				});
			}

			const response = await next(req);

			if (!response) {
				return response;
			}

			// Clone the response with CORS headers added
			// Response objects are immutable, so we need to create a new one
			const newHeaders = new Headers(response.headers);
			for (const [key, value] of Object.entries(corsHeaders)) {
				newHeaders.set(key, value);
			}

			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		};

		app.middleware(middleware);
	};
};
