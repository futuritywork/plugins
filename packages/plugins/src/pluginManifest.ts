import { z } from "zod";

/** Manifest protocol version emitted by this SDK. */
export const PLUGIN_MANIFEST_SPEC_VERSION = 4;

const HttpUrlSchema = z.url({ protocol: /^https?$/ });

/** Signed integration display and setup metadata supported by custom registration. */
const IntegrationMetadataSchema = z.object({
  tagline: z.string().optional(),
  oauth: z
    .object({
      token_body: z.enum(["form", "json"]).optional(),
      setup_steps: z.array(z.string()).optional(),
      console_url: HttpUrlSchema.optional(),
    })
    .optional(),
  overview: z.string().optional(),
  features: z
    .array(
      z.object({
        title: z.string(),
        description: z.string(),
        category: z.enum(["read", "write", "read_write"]),
        icon: z.string().optional(),
      }),
    )
    .optional(),
  permissions: z
    .array(
      z.union([
        z.object({
          scope: z.string(),
          label: z.string(),
          description: z.string(),
          access: z.enum(["read", "write", "read_write", "admin"]),
          docsUrl: HttpUrlSchema.nullable(),
        }),
        z.string(),
      ]),
    )
    .optional(),
  setupType: z.enum(["user", "admin", "none"]).optional(),
  links: z
    .object({
      docs: HttpUrlSchema.optional(),
      privacy: HttpUrlSchema.optional(),
    })
    .optional(),
});

const CredentialFieldSchema = z.object({
  key: z.string().min(1),
  label: z.string(),
  type: z.enum(["input", "password", "textarea", "x509-keypair"]),
  required: z.boolean().optional(),
  placeholder: z.string().optional(),
  help: z.string().optional(),
  // Keep this key in validation so unsupported regexes cannot be silently stripped.
  pattern: z.never().optional(),
  secondaryKey: z.string().optional(),
});

const CredentialsSchema = z
  .array(CredentialFieldSchema)
  .superRefine((fields, ctx) => {
    const keys = new Set<string>();
    fields.forEach((field, index) => {
      if (
        field.type === "x509-keypair"
          ? !field.secondaryKey
          : field.secondaryKey !== undefined
      ) {
        ctx.addIssue({
          code: "custom",
          message: "secondaryKey is required only for x509-keypair fields",
          path: [index, "secondaryKey"],
        });
      }
      for (const key of [
        field.key,
        ...(field.secondaryKey !== undefined ? [field.secondaryKey] : []),
      ]) {
        if (keys.has(key)) {
          ctx.addIssue({
            code: "custom",
            message: "Credential keys must be unique",
            path: [index],
          });
        }
        keys.add(key);
      }
    });
  })
  .nullable()
  .optional();

// Auth Forwarding Schema (platform manages tokens, forwards to plugin)
// Supports authorization_code (user-initiated OAuth), client_credentials, and saml2-bearer
// (admin-configured). When grantType is not authorization_code, authorizationEndpoint is
// not needed since there is no user redirect.
export const AuthForwardingSchema = z
  .object({
    type: z.literal("forwarding"),
    credentials_schema: CredentialsSchema,
    extra_params: z.record(z.string(), z.string()).nullable().optional(),
    tokenEndpoint: z.union([
      HttpUrlSchema,
      z.string().regex(/^\/(?![/\\])[^\s#\\]*$/),
    ]),
    authorizationEndpoint: HttpUrlSchema.optional(),
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
  })
  .refine(
    (auth) =>
      auth.grantType !== "authorization_code" ||
      !auth.tokenEndpoint.startsWith("/"),
    {
      message: "OAuth authorization_code requires an absolute tokenEndpoint",
      path: ["tokenEndpoint"],
    },
  );

/** Standalone chained-runtime configuration; excluded from v4 custom manifests. */
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

/** No OAuth exchange; explicit organization grants can collect credentials. */
export const NoAuthSchema = z.object({
  type: z.literal("none"),
  credentials_schema: CredentialsSchema,
  grantType: z.enum(["none", "api_key", "credentials"]).optional(),
  deliveryMethod: z.enum(["header", "query"]).optional(),
});

// Discriminated union for auth types
export const AuthSchema = z.discriminatedUnion("type", [
  AuthForwardingSchema,
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
  fields: z.array(DatasetFieldSchema).min(1),
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
    for (const id of Object.keys(data.datasets)) {
      if (!/^[^.\s]+$/.test(id)) {
        ctx.addIssue({
          code: "custom",
          message: `Data set id "${id}" has a dot or space; a data set id has neither.`,
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

/** Keys collected by explicit credential forms; other grants have no required keys. */
const requiredCredentialKeys: Partial<Record<NonNullable<z.infer<typeof AuthSchema>["grantType"]>, readonly string[]>> = {
  api_key: ["api_key"],
  client_credentials: ["api_base_url", "client_id", "client_secret"],
  "urn:ietf:params:oauth:grant-type:saml2-bearer": [
    "api_base_url",
    "client_id",
    "saml_subject_name_id",
    "private_key_pem",
    "public_cert_pem",
  ],
};

/** A v4 custom-plugin producer manifest with validated auth and optional data governance. */
export const PluginManifestSchema = z
  .object({
    specVersion: z.literal(PLUGIN_MANIFEST_SPEC_VERSION),
    pluginId: z.string().min(1),
    /** Developer or support contact included in the signed manifest. */
    developerEmail: z.email(),
    name: z.string().min(1),
    version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.0.0)"),
    icon: HttpUrlSchema.optional(),
    description: z.string().nullable().optional(),
    category: z.string().nullable().optional(),
    metadata: IntegrationMetadataSchema.nullable().optional(),
    auth: AuthSchema,
    mcpUrl: HttpUrlSchema,
    governance: GovernanceSchema.optional(),
  })
  .superRefine(({ auth }, ctx) => {
    const grant = auth.grantType ?? "none";
    const fields = auth.credentials_schema;
    const issue = (message: string) =>
      ctx.addIssue({
        code: "custom",
        message,
        path: ["auth", "credentials_schema"],
      });
    if (grant === "none" && fields?.length)
      issue("A none grant cannot collect credentials");
    if (grant === "credentials" && !fields?.length)
      issue("A credentials grant requires fields");
    // Null/omitted fields use platform defaults; explicit arrays must collect each grant key.
    if (fields != null) {
      const required = requiredCredentialKeys[grant] ?? [];
      const keys = new Set(
        fields.flatMap((field) => [
          field.key,
          ...(field.secondaryKey ? [field.secondaryKey] : []),
        ]),
      );
      for (const key of required) {
        if (!keys.has(key))
          issue(`auth.credentials_schema must collect ${key} for ${grant}`);
      }
    }
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

/** Author-supplied manifest fields; the SDK applies schema defaults and adds specVersion before signing. */
export interface PluginManifestOptions extends Omit<z.input<typeof PluginManifestSchema>, "specVersion"> {
  signingKey: string;
}
