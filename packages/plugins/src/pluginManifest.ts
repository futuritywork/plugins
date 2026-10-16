import { z } from "zod";

// Auth Forwarding Schema (platform manages tokens, forwards to plugin)
// Supports authorization_code (user-initiated OAuth), client_credentials, and saml2-bearer
// (admin-configured). When grantType is not authorization_code, authorizationEndpoint is
// not needed since there is no user redirect.
export const AuthForwardingSchema = z.object({
  type: z.literal("forwarding"),
  tokenEndpoint: z.url(),
  authorizationEndpoint: z.url().optional(),
  grantType: z
    .enum([
      "authorization_code",
      "client_credentials",
      "urn:ietf:params:oauth:grant-type:saml2-bearer",
    ])
    .default("authorization_code"),
  requiredScopes: z.array(z.string()).default([]),
  deliveryMethod: z.enum(["header", "query"]).default("header"),
  maxTokenTtl: z.number().positive().optional(),
});

// Chained Auth Schema (plugin manages its own sessions and stores third-party tokens)
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

/** A public plugin that needs no credentials. */
export const NoAuthSchema = z.object({
  type: z.literal("none"),
  deliveryMethod: z.enum(["header", "query"]).optional(),
});

// Discriminated union for auth types
export const AuthSchema = z.discriminatedUnion("type", [
  AuthForwardingSchema,
  ChainedAuthSchema,
  NoAuthSchema,
]);

const DatasetFieldSchema = z.object({
  name: z.string().min(1),
  type: z.string().min(1),
  identifier: z.string().min(1).optional(), // what the value matches elsewhere in the same system
  references: z
    .object({ dataset: z.string().min(1), field: z.string().min(1) })
    .optional(), // the declared column this one's values match
  nullable: z.boolean().optional(), // absent = unknown
  clock: z.enum(["wall", "instant"]).optional(),
  unit: z.string().min(1).optional(),
});

const DatasetSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  group: z.string().optional(),
  paths: z.array(z.string().min(1)).optional(), // upstream paths for audit and conformance
  fields: z.array(DatasetFieldSchema).optional(),
  probe: z
    .object({ tool: z.string().min(1), args: z.record(z.string(), z.unknown()) })
    .optional(),
});

/** Declared data sets, their field relationships, and default access policy. */
export const GovernanceSchema = z
  .object({
    timezone: z.string().min(1).optional(),
    // what the system is for; routing reads it when two systems hold the same noun
    purpose: z.string().min(1).optional(),
    credential: z.enum(["organization", "user"]),
    datasets: z.record(z.string(), DatasetSchema),
    defaultAccess: z.enum(["open", "restricted"]).optional(),
    restrictedByDefault: z.array(z.string()).optional(),
  })
  .superRefine((data, ctx) => {
    for (const [id, set] of Object.entries(data.datasets)) {
      if (!/^[^.\s]+$/.test(id)) {
        ctx.addIssue({
          code: "custom",
          message: `Data set id "${id}" has a dot or space; a data set id has neither.`,
          path: ["datasets", id],
        });
      }
      if (!set.fields?.length) {
        ctx.addIssue({
          code: "custom",
          message: `Data set "${id}" declares no fields; list at least one.`,
          path: ["datasets", id],
        });
      }
    }
  })
  .refine(
    (data) =>
      (data.restrictedByDefault ?? []).every((id) => Object.hasOwn(data.datasets, id)),
    {
      message: "restrictedByDefault names a data set that is not declared",
      path: ["restrictedByDefault"],
    },
  )
  .refine(
    (data) =>
      Object.values(data.datasets).every((set) =>
        (set.fields ?? []).every(
          ({ references }) =>
            !references ||
            (data.datasets[references.dataset]?.fields ?? []).some(
              (field) => field.name === references.field,
            ),
        ),
      ),
    {
      message: "a field references a data set or field that is not declared",
      path: ["datasets"],
    },
  );

/** A v3 producer manifest with validated auth and optional data governance. */
export const PluginManifestSchema = z
  .object({
    specVersion: z.literal(3),
    pluginId: z.string().min(1),
    name: z.string().min(1),
    version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.0.0)"),
    icon: z.string().optional(),
    auth: AuthSchema,
    mcpUrl: z.url(),
    governance: GovernanceSchema.optional(),
  })
  .refine(
    (data) => {
      if (data.auth.type !== "forwarding") return true;
      return (
        data.auth.grantType !== "authorization_code" ||
        data.auth.authorizationEndpoint
      );
    },
    {
      message:
        "authorizationEndpoint is required when grantType is authorization_code",
      path: ["auth", "authorizationEndpoint"],
    },
  );

export type PluginManifest = z.infer<typeof PluginManifestSchema>;
export type Auth = z.infer<typeof AuthSchema>;
export type AuthForwarding = z.infer<typeof AuthForwardingSchema>;
export type ChainedAuth = z.infer<typeof ChainedAuthSchema>;
export type Governance = z.infer<typeof GovernanceSchema>;

export interface PluginManifestOptions extends PluginManifest {
  signingKey: string;
}
