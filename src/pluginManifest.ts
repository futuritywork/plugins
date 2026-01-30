import { z } from "zod";

// v1 Auth Forwarding Schema (platform manages tokens, forwards to plugin)
export const AuthForwardingSchema = z.object({
  type: z.literal("forwarding"),
  tokenEndpoint: z.url(),
  authorizationEndpoint: z.url(),
  requiredScopes: z.array(z.string()).default([]),
  deliveryMethod: z.enum(["header", "query"]).default("header"),
  maxTokenTtl: z.number().positive().optional(),
});

// v2 Chained Auth Schema (plugin manages its own sessions and stores third-party tokens)
export const ChainedAuthSchema = z.object({
  type: z.literal("chained"),

  // Plugin's auth endpoints
  authorizationEndpoint: z.url(), // Start auth flow
  callbackEndpoint: z.url(), // External OAuth callback
  tokenEndpoint: z.url().optional(), // Token refresh (optional)

  // User context from platform
  requiredUserContext: z
    .array(z.enum(["user_id", "email", "organization_id", "display_name"]))
    .default(["user_id"]),

  // External services (informational)
  externalServices: z
    .array(
      z.object({
        name: z.string(),
        authorizationEndpoint: z.url(),
        requiredScopes: z.array(z.string()).default([]),
      })
    )
    .optional(),

  // Session config
  sessionConfig: z
    .object({
      maxSessionDuration: z.number().positive().optional(),
      supportsRefresh: z.boolean().default(false),
    })
    .optional(),
});

// Discriminated union for auth types
export const AuthSchema = z.discriminatedUnion("type", [
  AuthForwardingSchema,
  ChainedAuthSchema,
]);

export const PluginManifestSchema = z.object({
  specVersion: z.number().int().min(1).max(2),
  pluginId: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.0.0)"),
  auth: AuthSchema,
  mcpUrl: z.url(),
});

// Legacy schema for backward compatibility (v1 with authForwarding field)
export const PluginManifestSchemaV1 = z.object({
  specVersion: z.literal(1),
  pluginId: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.0.0)"),
  authForwarding: AuthForwardingSchema.omit({ type: true }),
  mcpUrl: z.url(),
});

// Combined schema that accepts both v1 (authForwarding) and v2 (auth) formats
export const PluginManifestSchemaCompat = z.union([
  PluginManifestSchema,
  PluginManifestSchemaV1.transform((v1) => ({
    specVersion: v1.specVersion,
    pluginId: v1.pluginId,
    name: v1.name,
    version: v1.version,
    mcpUrl: v1.mcpUrl,
    auth: {
      type: "forwarding" as const,
      ...v1.authForwarding,
    },
  })),
]);

export type PluginManifest = z.infer<typeof PluginManifestSchema>;
export type Auth = z.infer<typeof AuthSchema>;
export type AuthForwarding = z.infer<typeof AuthForwardingSchema>;
export type ChainedAuth = z.infer<typeof ChainedAuthSchema>;

export interface PluginManifestOptions extends PluginManifest {
  signingKey: string;
}
