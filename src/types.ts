export type Next = (req: Request) => Promise<Response | undefined>;
export type Middleware = (req: Request, next: Next) => Promise<Response | undefined>;
export type AuthMiddleware = (req: Request) => Promise<boolean> | boolean;

export interface WellKnownEntry {
	body: unknown;
	headers?: Record<string, string>;
}

