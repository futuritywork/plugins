import { z } from "zod";
import { PLACEHOLDER, placeholders } from "./placeholders";

export const FUTURITY_META_KEY = "work.futurity/plugin";

export const SPEC_VERSION = 5;

const SERVER_NAME = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;
const SEMVER = /^\d+\.\d+\.\d+$/;
const DELIVERY_HEADER = /^X-[A-Za-z0-9-]+$/;
const RESPONSE_PATH = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const HOLDERS = ["org", "user", "plugin", "none"] as const;
const ASSERTION_GRANTS = new Set(["jwt_bearer", "saml_bearer"]);

type SchemaMode = { development: boolean };

/** The scheme must be literal; the host may be a placeholder for an install-scoped setup value an org admin sets. */
function urlProblem(text: string, { development }: SchemaMode): string | undefined {
  let url: URL;
  try {
    url = new URL(text.replace(PLACEHOLDER, "placeholder"));
  } catch {
    return "must be an absolute URL";
  }
  if (url.protocol === "https:") return undefined;
  if (development && url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname)) return undefined;
  return development ? "must use https (http only for localhost)" : "must use https";
}

function urlSchema(mode: SchemaMode) {
  return z.string().superRefine((text, ctx) => {
    const problem = urlProblem(text, mode);
    if (problem) ctx.addIssue({ code: "custom", message: problem });
  });
}

function headerProblem(header: string): string | undefined {
  return DELIVERY_HEADER.test(header)
    ? undefined
    : "must match ^X-[A-Za-z0-9-]+$ (Authorization is reserved for the Futurity identity token)";
}

const CredentialFieldSchemaBase = z
  .strictObject({
    key: z.string().min(1),
    label: z.string().min(1),
    description: z.string().optional(),
    kind: z.enum(["setup", "futurity_secret", "plugin_secret"]),
    scope: z.enum(["install", "connect"]),
    input: z.enum(["text", "password", "textarea", "x509-keypair"]),
    secondaryKey: z.string().min(1).optional(),
    required: z.boolean().optional(),
    default: z.string().optional(),
    choices: z.array(z.string()).min(1).optional(),
    placeholder: z.string().optional(),
    help: z.string().optional(),
    header: z.string().optional(),
  })
  .superRefine((field, ctx) => {
    if (field.input === "x509-keypair" && field.secondaryKey === undefined) {
      ctx.addIssue({ code: "custom", path: ["secondaryKey"], message: "an x509-keypair field needs a secondaryKey" });
    }
    if (field.input !== "x509-keypair" && field.secondaryKey !== undefined) {
      ctx.addIssue({ code: "custom", path: ["secondaryKey"], message: "only an x509-keypair field takes a secondaryKey" });
    }
    if (field.kind === "futurity_secret") {
      if (field.header !== undefined) {
        ctx.addIssue({ code: "custom", path: ["header"], message: "a futurity_secret field is never delivered, so it takes no header" });
      }
      return;
    }
    if (field.header === undefined) {
      if (field.kind === "plugin_secret") {
        ctx.addIssue({ code: "custom", path: ["header"], message: "a plugin_secret field needs a delivery header" });
      }
      return;
    }
    const problem = headerProblem(field.header);
    if (problem) ctx.addIssue({ code: "custom", path: ["header"], message: problem });
  });

function oauthMethodSchema(mode: SchemaMode) {
  return z
    .strictObject({
      type: z.literal("oauth"),
      grant: z.enum(["authorization_code", "client_credentials", "jwt_bearer", "saml_bearer"]),
      authorizationUrl: urlSchema(mode).optional(),
      tokenUrl: urlSchema(mode),
      scopes: z.array(z.string().min(1)).optional(),
      authParams: z.record(z.string(), z.string()).optional(),
      tokenParams: z.record(z.string(), z.string()).optional(),
      actsAs: z.literal("user").optional(),
      client: z.enum(["futurity", "install", "dcr"]),
      delivery: z.union([z.strictObject({ header: z.string() }), z.literal("mcp_authorization")]),
      tokenRequest: z.strictObject({ encoding: z.enum(["form", "json"]) }).optional(),
      tokenResponseFields: z
        .array(
          z.strictObject({
            key: z.string().min(1),
            path: z.string().regex(RESPONSE_PATH, "must be a dotted path of property names, e.g. instance_url"),
            header: z.string(),
          }),
        )
        .optional(),
      callbackQueryFields: z
        .array(z.strictObject({ key: z.string().min(1), param: z.string().min(1), header: z.string() }))
        .optional(),
      pkce: z.boolean().optional(),
    })
    .superRefine((method, ctx) => {
      if (method.grant === "authorization_code" && method.authorizationUrl === undefined) {
        ctx.addIssue({ code: "custom", path: ["authorizationUrl"], message: "the authorization_code grant needs an authorizationUrl" });
      }
      if (method.grant !== "authorization_code" && method.authorizationUrl !== undefined) {
        ctx.addIssue({ code: "custom", path: ["authorizationUrl"], message: "only the authorization_code grant takes an authorizationUrl" });
      }
      if (method.actsAs !== undefined && !ASSERTION_GRANTS.has(method.grant)) {
        ctx.addIssue({ code: "custom", path: ["actsAs"], message: "actsAs applies only to the jwt_bearer and saml_bearer grants" });
      }
      if (typeof method.delivery === "object") {
        const problem = headerProblem(method.delivery.header);
        if (problem) ctx.addIssue({ code: "custom", path: ["delivery", "header"], message: problem });
      }
      if (method.pkce !== undefined && method.grant !== "authorization_code") {
        ctx.addIssue({ code: "custom", path: ["pkce"], message: "only the authorization_code grant takes pkce" });
      }
      if (method.tokenResponseFields !== undefined && method.delivery === "mcp_authorization") {
        ctx.addIssue({ code: "custom", path: ["tokenResponseFields"], message: 'delivery "mcp_authorization" sends nothing from Futurity, so it takes no tokenResponseFields' });
      }
      method.tokenResponseFields?.forEach((field, index) => {
        const problem = headerProblem(field.header);
        if (problem) ctx.addIssue({ code: "custom", path: ["tokenResponseFields", index, "header"], message: problem });
      });
      if (method.callbackQueryFields !== undefined && method.grant !== "authorization_code") {
        ctx.addIssue({ code: "custom", path: ["callbackQueryFields"], message: "only the authorization_code grant has an authorization redirect, so only it takes callbackQueryFields" });
      }
      if (method.callbackQueryFields !== undefined && method.delivery === "mcp_authorization") {
        ctx.addIssue({ code: "custom", path: ["callbackQueryFields"], message: 'delivery "mcp_authorization" sends nothing from Futurity, so it takes no callbackQueryFields' });
      }
      method.callbackQueryFields?.forEach((field, index) => {
        const problem = headerProblem(field.header);
        if (problem) ctx.addIssue({ code: "custom", path: ["callbackQueryFields", index, "header"], message: problem });
      });
    });
}

type OAuthMethodShape = z.infer<ReturnType<typeof oauthMethodSchema>>;
type FieldShape = z.infer<typeof CredentialFieldSchemaBase>;

/** A member-entered value must never pick where org secrets are sent, so placeholders name only admin-set fields. */
function isAdminSetupField(field: FieldShape, key: string): boolean {
  return field.key === key && field.kind === "setup" && field.scope === "install";
}

/** Every text in an OAuth method that may carry `{fieldKey}` placeholders, with its path. */
function templatedTexts(method: OAuthMethodShape): [path: (string | number)[], text: string][] {
  const texts: [(string | number)[], string][] = [[["tokenUrl"], method.tokenUrl]];
  if (method.authorizationUrl !== undefined) texts.push([["authorizationUrl"], method.authorizationUrl]);
  for (const params of ["authParams", "tokenParams"] as const) {
    for (const [name, value] of Object.entries(method[params] ?? {})) texts.push([[params, name], value]);
  }
  return texts;
}

function credentialOptionSchema(mode: SchemaMode) {
  return z
    .strictObject({
      id: z.string().min(1),
      label: z.string().min(1),
      holder: z.enum(HOLDERS),
      method: z.discriminatedUnion("type", [
        oauthMethodSchema(mode),
        z.strictObject({ type: z.literal("secrets") }),
        z.strictObject({ type: z.literal("none") }),
      ]),
      fields: z.array(CredentialFieldSchemaBase),
      setupSteps: z.array(z.string().min(1)).min(1).optional(),
    })
    .superRefine((option, ctx) => {
      const { holder, method, fields } = option;
      const issue = (path: (string | number)[], message: string) => ctx.addIssue({ code: "custom", path, message });

      const responseFields = method.type === "oauth" ? (method.tokenResponseFields ?? []) : [];
      const callbackFields = method.type === "oauth" ? (method.callbackQueryFields ?? []) : [];

      const keys = new Set<string>();
      const claimKey = (key: string, path: (string | number)[]) => {
        if (keys.has(key)) issue(path, `field key "${key}" is used twice in this option`);
        keys.add(key);
      };
      fields.forEach((field, index) => {
        for (const key of [field.key, field.secondaryKey]) {
          if (key !== undefined) claimKey(key, ["fields", index, "key"]);
        }
      });
      responseFields.forEach((field, index) => claimKey(field.key, ["method", "tokenResponseFields", index, "key"]));
      callbackFields.forEach((field, index) => claimKey(field.key, ["method", "callbackQueryFields", index, "key"]));

      const headers = new Map<string, (string | number)[]>();
      const claimHeader = (header: string, path: (string | number)[]) => {
        const name = header.toLowerCase();
        if (headers.has(name)) issue(path, `header "${header}" is used twice in this option`);
        headers.set(name, path);
      };
      fields.forEach((field, index) => {
        if (field.header !== undefined) claimHeader(field.header, ["fields", index, "header"]);
      });
      if (method.type === "oauth" && typeof method.delivery === "object") {
        claimHeader(method.delivery.header, ["method", "delivery", "header"]);
      }
      responseFields.forEach((field, index) => claimHeader(field.header, ["method", "tokenResponseFields", index, "header"]));
      callbackFields.forEach((field, index) => claimHeader(field.header, ["method", "callbackQueryFields", index, "header"]));

      if ((holder === "none" || holder === "plugin") && method.type !== "none") {
        issue(["method"], `holder "${holder}" requires method "none"`);
      }

      if (method.type === "none") {
        fields.forEach((field, index) => {
          if (field.kind !== "setup") issue(["fields", index, "kind"], 'method "none" allows only setup fields');
        });
      }

      if (method.type === "secrets" && !fields.some((field) => field.kind === "plugin_secret")) {
        issue(["fields"], 'method "secrets" needs at least one plugin_secret field');
      }

      if (holder === "org") {
        fields.forEach((field, index) => {
          if (field.scope === "connect") issue(["fields", index, "scope"], 'holder "org" fields are entered once at install, so scope "connect" is not allowed');
        });
      }

      if (method.type !== "oauth") return;

      fields.forEach((field, index) => {
        if (field.kind === "plugin_secret") issue(["fields", index, "kind"], 'method "oauth" does not allow plugin_secret fields');
      });

      if (holder === "user" && method.grant !== "authorization_code" && method.actsAs !== "user") {
        issue(["method", "actsAs"], `holder "user" with the ${method.grant} grant requires actsAs "user"`);
      }

      if (method.client === "install") {
        if (ASSERTION_GRANTS.has(method.grant)) {
          const privateKey = (field: FieldShape) =>
            field.kind === "futurity_secret" && field.scope === "install" && (field.key === "private_key" || field.input === "x509-keypair");
          if (!fields.some(privateKey)) {
            issue(["fields"], `client "install" with the ${method.grant} grant needs an install-scoped futurity_secret private key (key "private_key" or input "x509-keypair")`);
          }
        } else {
          const clientId = (field: FieldShape) => field.key === "client_id" && field.kind === "setup" && field.scope === "install";
          const clientSecret = (field: FieldShape) => field.key === "client_secret" && field.kind === "futurity_secret" && field.scope === "install";
          if (!fields.some(clientId)) issue(["fields"], 'client "install" needs an install-scoped setup field "client_id"');
          if (!fields.some(clientSecret)) issue(["fields"], 'client "install" needs an install-scoped futurity_secret field "client_secret"');
        }
      }

      for (const [path, text] of templatedTexts(method)) {
        for (const key of placeholders(text)) {
          if (!fields.some((field) => isAdminSetupField(field, key))) {
            issue(["method", ...path], `placeholder {${key}} does not name an install-scoped setup field of this option`);
          }
        }
      }
    });
}

function futurityExtensionSchema(mode: SchemaMode) {
  return z
    .strictObject({
      specVersion: z.literal(SPEC_VERSION),
      developer: z.strictObject({ name: z.string().min(1).optional(), email: z.email() }),
      category: z.string().min(1).optional(),
      listing: z
        .strictObject({
          tagline: z.string().optional(),
          overview: z.string().optional(),
          features: z.array(z.strictObject({ title: z.string().min(1), description: z.string() })).optional(),
          links: z.strictObject({ docs: urlSchema(mode).optional(), privacy: urlSchema(mode).optional() }).optional(),
        })
        .optional(),
      credentials: z.array(credentialOptionSchema(mode)).min(1, "declare at least one credential option"),
    })
    .superRefine(({ credentials }, ctx) => {
      const ids = new Set<string>();
      credentials.forEach((option, index) => {
        if (ids.has(option.id)) ctx.addIssue({ code: "custom", path: ["credentials", index, "id"], message: `credential option id "${option.id}" is used twice` });
        ids.add(option.id);
      });
    });
}

function pluginManifestSchema(mode: SchemaMode) {
  return z
    .object({
      name: z.string().regex(SERVER_NAME, "must be a reverse-DNS id such as work.futurity/esb"),
      title: z.string().min(1),
      description: z.string().min(1),
      version: z.string().regex(SEMVER, "must be semver x.y.z"),
      icons: z
        .array(z.strictObject({ src: urlSchema(mode), mimeType: z.string().optional(), sizes: z.array(z.string()).optional() }))
        .optional(),
      websiteUrl: urlSchema(mode).optional(),
      remotes: z.tuple([z.strictObject({ type: z.literal("streamable-http"), url: urlSchema(mode) })]),
      _meta: z.object({ [FUTURITY_META_KEY]: futurityExtensionSchema(mode) }),
    })
    .superRefine((manifest, ctx) => {
      const remote = manifest.remotes[0].url;
      const options = manifest._meta[FUTURITY_META_KEY].credentials;
      for (const key of placeholders(remote)) {
        const missing = options.filter((option) => !option.fields.some((field) => isAdminSetupField(field, key)));
        for (const option of missing) {
          ctx.addIssue({
            code: "custom",
            path: ["remotes", 0, "url"],
            message: `placeholder {${key}} does not name an install-scoped setup field of credential option "${option.id}"`,
          });
        }
      }
    });
}

const production: SchemaMode = { development: false };

/** Validates a manifest for production: every URL is https. */
export const PluginManifestSchema = pluginManifestSchema(production);

/** Validates a manifest for local development: http is also accepted for localhost. */
export const DevelopmentPluginManifestSchema = pluginManifestSchema({ development: true });

export const FuturityExtensionSchema = futurityExtensionSchema(production);
export const CredentialOptionSchema = credentialOptionSchema(production);
export const CredentialFieldSchema = CredentialFieldSchemaBase;
export const OAuthMethodSchema = oauthMethodSchema(production);

export type PluginManifest = z.infer<typeof PluginManifestSchema>;
export type PluginManifestInput = z.input<typeof PluginManifestSchema>;
export type FuturityExtension = z.infer<typeof FuturityExtensionSchema>;
export type CredentialOption = z.infer<typeof CredentialOptionSchema>;
export type CredentialField = z.infer<typeof CredentialFieldSchema>;
export type OAuthMethod = z.infer<typeof OAuthMethodSchema>;
export type Holder = CredentialOption["holder"];
