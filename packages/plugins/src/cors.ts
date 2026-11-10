import type { Middleware } from "./types";

export type CorsOptions = {
	/** The exact origins allowed to call the server; with none, no CORS headers are sent. */
	origins?: string[];
	allowMethods?: string[];
	allowHeaders?: string[];
	exposeHeaders?: string[];
	maxAge?: number;
	credentials?: boolean;
};

type MiddlewareHost = { middleware(middleware: Middleware): unknown };

export const cors = (options: CorsOptions) => {
	const origins = new Set(options.origins ?? []);
	if (origins.has("*")) throw new Error('cors() takes exact origins; "*" is not allowed');
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

	/** Only a listed origin gets CORS headers; every other caller gets none. */
	const getCorsHeaders = (req: Request): Record<string, string> | undefined => {
		const origin = req.headers.get("origin");
		if (origin === null || !origins.has(origin)) return undefined;
		const headers: Record<string, string> = {
			"Access-Control-Allow-Origin": origin,
			"Access-Control-Allow-Methods": allowMethods,
			"Access-Control-Allow-Headers": allowHeaders,
			"Access-Control-Expose-Headers": exposeHeaders,
			"Access-Control-Max-Age": maxAge,
			Vary: "Origin",
		};
		if (credentials) {
			headers["Access-Control-Allow-Credentials"] = "true";
		}
		return headers;
	};

	return (app: MiddlewareHost) => {
		const middleware: Middleware = async (req, next) => {
			const corsHeaders = getCorsHeaders(req);
			if (!corsHeaders) return next(req);

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

			// Response objects are immutable, so copy it with the CORS headers added
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
