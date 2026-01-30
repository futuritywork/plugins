import { z } from "zod";

export const AuthForwardingSchema = z.object({
  tokenEndpoint: z.url(),
  authorizationEndpoint: z.url(),
  requiredScopes: z.array(z.string()).default([]),
  deliveryMethod: z.enum(["header", "query"]).default("header"),
  maxTokenTtl: z.number().positive().optional(),
});

export const PluginManifestSchema = z.object({
  specVersion: z.number().int().min(1).max(1),
  pluginId: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.0.0)"),
  authForwarding: AuthForwardingSchema,
  mcpUrl: z.url(),
});

export type PluginManifest = z.infer<typeof PluginManifestSchema>;
export type AuthForwarding = z.infer<typeof AuthForwardingSchema>;

export interface PluginManifestOptions extends PluginManifest {
  signingKey: string;
}
