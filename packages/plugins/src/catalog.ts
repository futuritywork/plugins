import { z } from "zod";
import type { PluginManifest } from "./pluginManifest";

const HttpUrlSchema = z.url({ protocol: /^https?$/ });

// String inputs accept imported JSON; the output retains validated literal types.
const CredentialFieldSchema = z.object({
  key: z.string(),
  label: z.string(),
  type: z.string().pipe(z.enum(["input", "text", "password", "textarea", "x509-keypair"])),
  required: z.boolean().optional(),
  placeholder: z.string().optional(),
  help: z.string().optional(),
  pattern: z.string().optional(),
  secondaryKey: z.string().optional(),
}).strip();

// Keep this public projection compatible with Futurity's IntegrationMetadataSchema.
const MetadataSchema = z.object({
  tagline: z.string().optional(),
  overview: z.string().optional(),
  oauth: z.object({
    token_body: z.string().pipe(z.enum(["form", "json"])).optional(),
    setup_steps: z.array(z.string()).optional(),
    console_url: HttpUrlSchema.optional(),
  }).strip().optional(),
  features: z.array(z.object({
    title: z.string(),
    description: z.string(),
    category: z.string().pipe(z.enum(["read", "write", "read_write"])),
    icon: z.string().optional(),
  }).strip()).optional(),
  permissions: z.array(z.union([
    z.string(),
    z.object({
      scope: z.string(),
      label: z.string(),
      description: z.string(),
      access: z.string().pipe(z.enum(["read", "write", "read_write", "admin"])),
      docsUrl: HttpUrlSchema.nullable(),
    }).strip(),
  ])).optional(),
  setupType: z.string().pipe(z.enum(["user", "admin", "none"])).optional(),
  links: z.object({
    docs: HttpUrlSchema.optional(),
    privacy: HttpUrlSchema.optional(),
  }).strip().optional(),
}).strip();

/** Validates public catalog fields, strips unknown keys from fixed-shape objects, and applies wire defaults. */
export const CatalogOptionsSchema = z.object({
  slug: z.string().min(1).optional(),
  name: z.string().min(1).optional(),
  grant_type: z.string().min(1),
  mcp_url: z.url().optional(),
  description: z.string().nullable().default(null),
  category: z.string().nullable().default(null),
  icon_url: z.string().nullable().default(null),
  auth_url: z.string().nullable().default(null),
  token_url: z.string().nullable().default(null),
  scopes: z.string().nullable().default(null),
  extra_params: z.record(z.string(), z.string()).nullable().default(null),
  plugin_base_url: z.string().nullable().default(null),
  is_official: z.boolean().default(false),
  popular: z.boolean().default(false),
  credential_schema: z.array(CredentialFieldSchema).nullable().default(null),
  metadata: MetadataSchema.nullable().default(null),
  marketplace_sign_in: z.boolean().nullable().default(null),
  signing_public_key: z.string().nullable().default(null),
}).strip();

/**
 * Public marketplace metadata for one plugin; grant_type is required.
 * McpApp derives slug, name, and mcp_url from its validated pluginManifest.
 * These optional input fields allow existing JSON configs; manifest values always
 * override them, even when supplied values are stale. No auth fields are inferred.
 * Omitted optional fields become null, except is_official/popular (false) and
 * fields within metadata/credentials.
 * marketplace_sign_in is explicit or null; signing_public_key is an explicit
 * SPKI DER base64 public key. All recognized values, including extra_params, are public.
 */
export type CatalogOptions = z.input<typeof CatalogOptionsSchema>;

/**
 * Snapshots public metadata with authoritative identity from a validated manifest
 * as one JSON object for GET /api/catalog (405 for other methods). Unrelated paths return undefined;
 * missing or malformed catalog metadata throws a ZodError.
 */
export function createCatalogHandler(
  options: CatalogOptions,
  manifest: Pick<PluginManifest, "pluginId" | "name" | "mcpUrl">,
): (req: Request) => Response | undefined {
  const entry = CatalogOptionsSchema.parse({
    ...options,
    slug: manifest.pluginId,
    name: manifest.name,
    mcp_url: manifest.mcpUrl,
  });
  const auth_type = entry.grant_type === "none"
    ? "free"
    : entry.grant_type === "api_key"
      ? "api_key"
      : entry.credential_schema
        ? "admin"
        : "oauth";
  const body = JSON.stringify({ ...entry, auth_type });

  return (req) => {
    if (new URL(req.url).pathname !== "/api/catalog") return undefined;
    if (req.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET" } });
    }
    return new Response(body, { headers: { "Content-Type": "application/json" } });
  };
}
