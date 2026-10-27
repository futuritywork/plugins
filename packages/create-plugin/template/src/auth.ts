import { AsyncLocalStorage } from "node:async_hooks";
import type { Middleware } from "@futurity/plugins";

/**
 * Futurity sends two credentials on every tool call. `Authorization` carries
 * Futurity's own short-lived token, which identifies the platform. The token
 * your API cares about is in `X-Plugin-Access-Token`, and any extra fields the
 * administrator filled in ride along as JSON in `X-Futurity-Data-Params`.
 */
export type PluginRequest = {
  accessToken: string | null;
  dataParams: Record<string, string>;
};

const store = new AsyncLocalStorage<PluginRequest>();

/**
 * The credentials for the call being served. Tool handlers receive their input
 * only, so the request travels here instead of through an argument.
 */
export function currentRequest(): PluginRequest {
  return store.getStore() ?? { accessToken: null, dataParams: {} };
}

/** The forwarded token, or a thrown error when the caller sent none. */
export function requireAccessToken(): string {
  const { accessToken } = currentRequest();
  if (!accessToken) {
    throw new Error(
      "No X-Plugin-Access-Token on this request. Connect the integration in Futurity first.",
    );
  }
  return accessToken;
}

function parseDataParams(raw: string | null): Record<string, string> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    );
  } catch {
    return {};
  }
}

/**
 * Bind each request's credentials for the duration of that request. An async
 * store rather than a module variable, so overlapping calls cannot read each
 * other's token.
 */
export const forwardedAuth: Middleware = (req, next) =>
  store.run(
    {
      accessToken: req.headers.get("X-Plugin-Access-Token"),
      dataParams: parseDataParams(req.headers.get("X-Futurity-Data-Params")),
    },
    () => next(req),
  );

/**
 * The `client_credentials` token endpoint named by the manifest. Futurity posts
 * the credentials an administrator saved, caches what you return until shortly
 * before `expires_in`, and forwards `access_token` on every tool call.
 */
export const tokenEndpoint = (path: string): Middleware => {
  return async (req, next) => {
    if (new URL(req.url).pathname !== path) return next(req);
    if (req.method !== "POST") return next(req);

    const form = await req.formData();
    const clientId = String(form.get("client_id") ?? "");
    const clientSecret = String(form.get("client_secret") ?? "");

    if (!clientId || !clientSecret) {
      return Response.json({ error: "invalid_client" }, { status: 401 });
    }

    // YOUR CODE HERE: exchange these credentials with the system you wrap, and
    // return its token. The stub below lets the whole flow run end to end first.
    return Response.json({
      access_token: `${clientId}-demo-token`,
      token_type: "Bearer",
      expires_in: 3600,
    });
  };
};
