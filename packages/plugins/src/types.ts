export type Next = (req: Request) => Promise<Response | undefined>;
export type Middleware = (req: Request, next: Next) => Promise<Response | undefined>;
