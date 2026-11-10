# Manifest v5

A Futurity plugin publishes one manifest at `GET /.well-known/futurity/plugin`.
It is shaped like an MCP Registry `server.json`, with everything Futurity needs
under one `_meta` key, `work.futurity/plugin`. The manifest is plain JSON with no
signature: Futurity pins the content an admin approved, and any later change
waits as a pending revision until an admin approves it.

`@futurity/plugin-manifest` is the only validator. The SDK, the platform and the
marketplace all call `parsePluginManifest`, so every rule below holds wherever a
manifest is read.

## Shape

```ts
type PluginManifest = {
  name: string;            // reverse-DNS id, e.g. "work.futurity/esb"
  title: string;
  description: string;
  version: string;         // semver x.y.z
  icons?: { src: string; mimeType?: string; sizes?: string[] }[];
  websiteUrl?: string;
  remotes: [{ type: "streamable-http"; url: string }];   // exactly one; url may contain {fieldKey}
  _meta: { "work.futurity/plugin": FuturityExtension };
};

type FuturityExtension = {
  specVersion: 5;
  developer: { name?: string; email: string };
  category?: string;
  listing?: {
    tagline?: string;
    overview?: string;
    features?: { title: string; description: string }[];
    links?: { docs?: string; privacy?: string };
  };
  credentials: CredentialOption[];   // at least one; an admin picks one per org at install
};

type CredentialOption = {
  id: string;                        // unique within the manifest
  label: string;
  holder: "org" | "user" | "plugin" | "none";
  method: OAuthMethod | { type: "secrets" } | { type: "none" };
  fields: CredentialField[];
  setupSteps?: string[];             // admin instructions shown at install, in order
};

type CredentialField = {
  key: string;                       // unique within the option
  label: string;
  description?: string;
  kind: "setup" | "futurity_secret" | "plugin_secret";
  scope: "install" | "connect";      // install = once by an org admin; connect = by each holder
  input: "text" | "password" | "textarea" | "x509-keypair";
  secondaryKey?: string;             // x509-keypair only
  required?: boolean;                // default true
  default?: string;
  choices?: string[];
  placeholder?: string;              // display hint inside an empty input
  help?: string;                     // display hint below the input
  header?: string;                   // delivery header; required for plugin_secret, optional for setup
};

type OAuthMethod = {
  type: "oauth";
  grant: "authorization_code" | "client_credentials" | "jwt_bearer" | "saml_bearer";
  authorizationUrl?: string;         // authorization_code only
  tokenUrl: string;
  scopes?: string[];
  authParams?: Record<string, string>;
  tokenParams?: Record<string, string>;
  actsAs?: "user";                   // jwt_bearer and saml_bearer only
  client: "futurity" | "install" | "dcr";
  delivery: { header: string } | "mcp_authorization";
  tokenRequest?: { encoding: "form" | "json" };   // token endpoint body; default "form"
  tokenResponseFields?: { key: string; path: string; header: string }[];
  callbackQueryFields?: { key: string; param: string; header: string }[];   // authorization_code only
  pkce?: boolean;                    // authorization_code only; default true
};
```

Unknown keys inside the Futurity extension are errors, so a retired key such as
`dangerLevel` fails loudly. Unknown keys at the top level and in `_meta` are
dropped, so a full `server.json` parses.

## Holders, methods and kinds

- `holder` says whose credential a call uses: the org's, the calling user's, the
  plugin's own account (`plugin`, treated like `org` for availability), or none.
- `method` says how Futurity gets it: an OAuth exchange Futurity runs, secrets an
  admin or user types in, or nothing.
- `kind` says where a field's value goes. `setup` values (a tenant, a region) are
  delivered to the plugin when the field has a `header`; a `setup` field without
  a header (an OAuth `client_id`, a value only `tokenParams` uses) is used only by
  Futurity, to fill placeholders, `authParams` and `tokenParams`, and never
  reaches the plugin. `plugin_secret` values (an API key) are always delivered to
  the plugin. `futurity_secret` values (a client secret, a private key) stay in
  Futurity and are used only for the OAuth exchange.

## Validation rules

Every parse enforces all of these.

1. `holder: "none"` and `holder: "plugin"` require `method: { type: "none" }`.
2. `method: none` allows only `setup` fields, so a none or plugin holder carries
   no secrets.
3. `method: secrets` needs at least one `plugin_secret` field.
4. `method: oauth` forbids `plugin_secret` fields.
5. `client: "install"` needs an install-scoped `setup` field `client_id` and an
   install-scoped `futurity_secret` field `client_secret`. On `jwt_bearer` and
   `saml_bearer` it needs instead an install-scoped `futurity_secret` private key:
   a field with key `private_key` or input `x509-keypair`.
6. `holder: "org"` forbids `scope: "connect"` fields.
7. `holder: "user"` with an OAuth grant other than `authorization_code` requires
   `actsAs: "user"`. `actsAs` is allowed only on `jwt_bearer` and `saml_bearer`,
   so a user-held `client_credentials` option is rejected.
8. `delivery: "mcp_authorization"` takes any client: `dcr` when the vendor's
   authorization server registers clients dynamically, `futurity` or `install`
   when it does not. An `install` client still needs the fields of rule 5.
9. Every `{fieldKey}` placeholder in `tokenUrl`, `authorizationUrl`,
   `authParams` or `tokenParams` names a `setup` field with `scope: "install"`
   in the same option. A placeholder in the remote URL must name such a field in
   every option, because an admin may install any of them. A `connect` field is
   typed by each member, so it can never choose where org secrets are sent.
10. `plugin_secret` fields need a `header`; a `setup` field may have one. Every
    header matches `^X-[A-Za-z0-9-]+$`. A `futurity_secret` field takes no
    header. An OAuth `delivery.header`, each `tokenResponseFields[].header` and
    each `callbackQueryFields[].header` follow the same pattern. Headers are
    unique within an option across fields, the delivery header, token response
    fields and callback query fields, compared without case.
    `Authorization` is reserved for the Futurity identity token.
11. URLs (remote, icons, website, links, OAuth endpoints) use https. With
    `{ development: true }`, `http://localhost`, `http://127.0.0.1` and
    `http://[::1]` are also accepted. A URL's scheme must be literal, but its host
    may be an install-time placeholder set by an org admin, so
    `https://{tenant}.example.com` passes and `{base}/mcp` does not; the platform
    checks the URL again after it fills the placeholders.
12. `authorization_code` needs an `authorizationUrl`, and other grants take none.
13. `x509-keypair` fields need a `secondaryKey`; other inputs take none. Keys,
    including secondary keys, are unique within an option. Option ids are unique
    within the manifest.
14. `pkce` is allowed only on `authorization_code`. Futurity uses PKCE (S256)
    unless `pkce` is `false`, for providers that reject it.
15. `tokenResponseFields` require `delivery: { header }`; a vendor server on
    `mcp_authorization` gets nothing from Futurity. Each `path` is a dotted path
    of property names into the token response JSON (`instance_url`,
    `team.id`). Each `key` is unique within the option, across field keys,
    secondary keys and callback query field keys.
16. `callbackQueryFields` are values Futurity copies from the query string of
    the authorization redirect, such as QuickBooks `realmId`. Each `param` is
    the query parameter name. They are allowed only with the
    `authorization_code` grant and require `delivery: { header }`. Each `key`
    is unique within the option, across field keys, secondary keys and token
    response field keys.
17. `tokenRequest.encoding` is `form` (`application/x-www-form-urlencoded`, the
    default) or `json` (`application/json`), the body Futurity sends to
    `tokenUrl` for the grant and for refreshes.
18. `placeholder`, `help` and `setupSteps` are display hints with no effect on
    validation or delivery. `setupSteps`, when present, holds at least one
    non-empty step.
19. `name` matches `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`, `version` is `x.y.z`,
    `remotes` holds exactly one `streamable-http` remote, and `credentials` holds
    at least one option.

An org install exists when any field has `scope: "install"` or the OAuth client
is `install`; `installRequired(option)` answers that.

## Delivery

Every call to `/mcp` carries:

- `Authorization: Bearer <jwt>`, signed by Futurity with the key published at
  `/oauth/jwks`. Claims: `iss` (the Futurity API origin), `aud` (the remote URL
  exactly as written in the manifest, placeholders included, never the resolved
  URL), `sub` (user id), `org_id`, `holder`, `credential_option`, `iat`, `exp`
  (at most five minutes after `iat`) and `jti`.
- One header per `setup` and `plugin_secret` field of the chosen option that
  declares a `header`.
- For OAuth with `delivery: { header }`, the access token in that header, and
  one header per `tokenResponseFields` entry carrying the value Futurity read at
  `path` from the token response (for example Salesforce `instance_url`), and
  one header per `callbackQueryFields` entry carrying the value Futurity read
  from `param` on the authorization redirect (for example QuickBooks
  `realmId`). The SDK requires each of these headers and exposes the values in
  `ctx.credentials` under `key`, beside `access_token`.

Setup fields without a header are never delivered.

A server with `delivery: "mcp_authorization"` is a vendor MCP server. It gets the
vendor's OAuth token in `Authorization` per the MCP spec and no Futurity token.
Futurity reads the server's protected resource metadata (RFC 9728) and its
authorization server's metadata (RFC 8414), and authorizes, exchanges and
refreshes at the endpoints that metadata names, sending the server's `resource`
(RFC 8707). A server that publishes no authorization server metadata is reached
at the option's `authorizationUrl` and `tokenUrl`. When the option declares no
`scopes`, Futurity asks for the scopes the protected resource metadata lists.

`FuturityIdentityClaimsSchema` validates the claims. The SDK trusts a list of
issuers, each with its own JWKS URL (`futurity: { issuers: [{ issuer, jwksUrl }] }`),
so one plugin deployment can serve production, staging and dev. An issuer such
as `https://*.futurity.work` with `jwksUrl: "/oauth/jwks"` trusts every subdomain
origin and fetches its keys from that origin. It picks the
JWKS by the token's `iss`, refuses any other issuer, verifies the signature,
issuer and audience with `jose`, and checks that `credential_option` names an
option in the manifest whose `holder` matches the token's. Any of those
failing is a 401. A required header of that option that is missing is a 400
`missing_credential`. It then hands handlers
`{ issuer, org, user, holder, credentials, signal }`. The SDK does not track
`jti`, so a replayed token is accepted until it expires.

The `iss` of each Futurity deployment:

| Deployment | `iss` | JWKS |
| --- | --- | --- |
| Production | `https://api-v4.futurity.work` | `https://api-v4.futurity.work/oauth/jwks` |
| Staging | `https://api-v4-staging.futurity.work` | `https://api-v4-staging.futurity.work/oauth/jwks` |
| Local development | `http://localhost:4000` | `http://localhost:4000/oauth/jwks` |

A self-hosted deployment issues tokens from its own `API_URL` origin.

## OAuth clients

- `client: "futurity"` uses an OAuth client Futurity's platform admins register
  for a marketplace plugin. It only works for plugins in the Futurity
  marketplace; an org-registered plugin with it fails at connect.
- `client: "install"` uses the organization's own client, entered at install as
  the `client_id` and `client_secret` fields (rule 5). Use it for a plugin your
  organization registers.
- `client: "dcr"` registers a client once with the server's authorization
  server through MCP dynamic client registration, when the plugin is
  registered. It is supported for `holder: "user"`; an org-held `dcr` option is
  not supported yet.

A vendor server whose authorization server offers no dynamic registration
still works with `delivery: "mcp_authorization"`: a marketplace entry uses
`client: "futurity"` with the client Futurity registered with the vendor (for
example GitHub's MCP server), and an organization that registers the server
itself uses `client: "install"` with its own OAuth app.

## Assertion grants

`jwt_bearer` (RFC 7523) and `saml_bearer` (RFC 7522) are signed by Futurity
with the install's private key (a `futurity_secret` field keyed `private_key`,
or an `x509-keypair` field). Futurity reads these install `setup` field keys by
name, so declare them with exactly these keys when the provider needs them:

| Field key | Used for | When absent |
| --- | --- | --- |
| `client_id` | The JWT `iss` and the `client_id` sent with the token request; for SAML, the API key sent as `client_id` | Empty |
| `subject` | The assertion subject when `actsAs` is not `"user"` | `client_id` |
| `saml_issuer` | The SAML assertion `Issuer` (`saml_bearer` only) | The Futurity API origin |
| `saml_audience` | The SAML assertion `Audience` (`saml_bearer` only) | `tokenUrl` |

With `actsAs: "user"`, the subject is the calling member's email address. A
`saml_bearer` option needs an `x509-keypair` field, because the assertion
carries the certificate (`secondaryKey`). The JWT audience is always the filled
`tokenUrl`.

## Tool safety

Futurity reads danger from standard MCP tool annotations only, through
`toolDanger(annotations)`:

- `readOnlyHint: true` is `read`.
- otherwise `destructiveHint: true` is `delete`.
- anything else is `write`.

Admins set `allow`, `ask` or `block` per group and per tool.

## Tool output

The manifest does not carry tools. `@futurity/plugins` requires every tool to
declare `output`, and advertises it as `outputSchema` in `tools/list`.

A third-party MCP server may leave `outputSchema` out. Futurity connects it all
the same and shows the tool as "Returns: not declared", since it cannot tell
what the tool returns.

## Package API

```ts
import {
  parsePluginManifest,          // (json, { development? }) => { success, manifest } | { success, errors }
  PluginManifestSchema,         // production rules
  DevelopmentPluginManifestSchema,
  FuturityExtensionSchema,
  CredentialOptionSchema,
  CredentialFieldSchema,
  OAuthMethodSchema,
  FuturityIdentityClaimsSchema,
  FUTURITY_META_KEY,            // "work.futurity/plugin"
  futurityExtension,            // manifest => its _meta extension
  installRequired,              // option => boolean
  fieldsFor,                    // (option, scope) => fields entered at that step
  placeholders,                 // text => distinct {fieldKey} names
  toolDanger,                   // annotations => "read" | "write" | "delete"
} from "@futurity/plugin-manifest";
```

Errors read as a path and a message, for example
`_meta["work.futurity/plugin"].credentials[0].fields[1].header: a plugin_secret field needs a delivery header`.

## Example

```json
{
  "name": "work.futurity/esb",
  "title": "ESB Core",
  "description": "Sales, stock and outlets from ESB Core",
  "version": "1.0.0",
  "remotes": [{ "type": "streamable-http", "url": "https://esb.plugins.futurity.work/mcp" }],
  "_meta": {
    "work.futurity/plugin": {
      "specVersion": 5,
      "developer": { "email": "plugins@futurity.work" },
      "credentials": [
        {
          "id": "company-key",
          "label": "Company API key",
          "holder": "org",
          "method": { "type": "secrets" },
          "fields": [
            { "key": "company_code", "label": "Company code", "kind": "setup", "scope": "install", "input": "text", "header": "X-Company-Code" },
            { "key": "api_key", "label": "API key", "kind": "plugin_secret", "scope": "install", "input": "password", "header": "X-Api-Key" }
          ]
        }
      ]
    }
  }
}
```

An OAuth option that reads a value from the token response, and one that sends
a JSON token body with PKCE off and an admin-entered client:

```json
[
  {
    "id": "salesforce-user",
    "label": "Sign in with Salesforce",
    "holder": "user",
    "method": {
      "type": "oauth",
      "grant": "authorization_code",
      "authorizationUrl": "https://login.salesforce.com/services/oauth2/authorize",
      "tokenUrl": "https://login.salesforce.com/services/oauth2/token",
      "client": "futurity",
      "delivery": { "header": "X-Salesforce-Token" },
      "tokenResponseFields": [{ "key": "instance_url", "path": "instance_url", "header": "X-Instance-Url" }]
    },
    "fields": []
  },
  {
    "id": "lark-app",
    "label": "Your Lark app",
    "holder": "user",
    "setupSteps": ["Create a custom app in the Lark developer console", "Paste its App ID and App Secret below"],
    "method": {
      "type": "oauth",
      "grant": "authorization_code",
      "authorizationUrl": "https://open.larksuite.com/open-apis/authen/v1/authorize",
      "tokenUrl": "https://open.larksuite.com/open-apis/authen/v2/oauth/token",
      "client": "install",
      "delivery": { "header": "X-Lark-Token" },
      "tokenRequest": { "encoding": "json" },
      "pkce": false
    },
    "fields": [
      { "key": "client_id", "label": "App ID", "kind": "setup", "scope": "install", "input": "text", "placeholder": "cli_a1b2c3" },
      { "key": "client_secret", "label": "App Secret", "kind": "futurity_secret", "scope": "install", "input": "password" }
    ]
  }
]
```
