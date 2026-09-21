# Chained OAuth Authentication

Chained OAuth is a v2 auth option where the plugin manages its own sessions and stores third-party tokens. Unlike auth forwarding (v1), the plugin has full control over the OAuth flow and token storage.

## Overview

```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│ Platform │      │  Plugin  │      │ External │      │ Platform │
│  (User)  │      │          │      │  OAuth   │      │  (MCP)   │
└────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘
     │                 │                 │                 │
     │ 1. Redirect     │                 │                 │
     │ (user JWT)      │                 │                 │
     │────────────────>│                 │                 │
     │                 │                 │                 │
     │                 │ 2. Redirect     │                 │
     │                 │────────────────>│                 │
     │                 │                 │                 │
     │                 │ 3. Callback     │                 │
     │                 │ (auth code)     │                 │
     │                 │<────────────────│                 │
     │                 │                 │                 │
     │ 4. Redirect     │                 │                 │
     │ (plugin token)  │                 │                 │
     │<────────────────│                 │                 │
     │                 │                 │                 │
     │                 │                 │ 5. MCP Request  │
     │                 │                 │ (plugin token + │
     │                 │                 │  assertion)     │
     │                 │<────────────────────────────────────
     │                 │                 │                 │
```

## Plugin Manifest (v2)

```typescript
const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  pluginManifest: {
    specVersion: 2,
    pluginId: "my-plugin",
    name: "My Plugin",
    version: "1.0.0",
    signingKey: process.env.PLUGIN_SIGNING_KEY!,
    auth: {
      type: "chained",
      authorizationEndpoint: "https://plugin.example.com/auth/authorize",
      callbackEndpoint: "https://plugin.example.com/auth/callback",
      tokenEndpoint: "https://plugin.example.com/auth/token", // optional
      requiredUserContext: ["user_id", "email", "organization_id"],
      externalServices: [
        {
          name: "Monday.com",
          authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
          requiredScopes: ["me:read", "boards:read"],
        },
      ],
      sessionConfig: {
        maxSessionDuration: 86400000, // 24 hours
        supportsRefresh: true,
      },
    },
    mcpUrl: "https://plugin.example.com/mcp",
  },
});
```

## Implementation

### 1. Configure Chained Auth

```typescript
import {
  mcp,
  createPendingSession,
  activateSession,
  generatePluginToken,
  generateChainedState,
  parseChainedState,
  InMemorySessionStore, // Use a real store in production
} from "@futuritywork/plugins";

const sessionStore = new InMemorySessionStore();

const app = mcp({
  name: "my-plugin",
  version: "1.0.0",
  chainedAuth: {
    sessionStore,
    platformJwksUrl: "https://platform.example.com/.well-known/jwks.json",
    pluginSigningKey: process.env.PLUGIN_SIGNING_KEY!,
    handlers: {
      onAuthorize,
      onCallback,
      onToken, // optional
    },
  },
});
```

### 2. Handle Authorization

```typescript
async function onAuthorize(
  userContext: UserContext,
  platformState: string,
  platformCallback: string
): Promise<Response> {
  // Create pending session
  const session = createPendingSession(
    userContext,
    platformState,
    platformCallback
  );
  await sessionStore.create(session);

  // Generate chained state (includes platform state + session ID)
  const chainedState = generateChainedState(platformState, session.id);

  // Redirect to external OAuth
  const authUrl = new URL("https://external.oauth.com/authorize");
  authUrl.searchParams.set("client_id", process.env.EXTERNAL_CLIENT_ID!);
  authUrl.searchParams.set("redirect_uri", "https://plugin.example.com/auth/callback");
  authUrl.searchParams.set("state", chainedState);
  authUrl.searchParams.set("scope", "read write");

  return Response.redirect(authUrl.toString(), 302);
}
```

### 3. Handle Callback

```typescript
async function onCallback(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code")!;
  const state = url.searchParams.get("state")!;

  // Parse chained state
  const { platform: platformState, session: sessionId } = parseChainedState(state);

  // Get pending session
  const session = await sessionStore.get(sessionId);
  if (!session || session.state !== "pending") {
    return new Response("Invalid session", { status: 400 });
  }

  // Exchange code for external token
  const tokenResponse = await fetch("https://external.oauth.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: process.env.EXTERNAL_CLIENT_ID!,
      client_secret: process.env.EXTERNAL_CLIENT_SECRET!,
      redirect_uri: "https://plugin.example.com/auth/callback",
    }),
  });
  const externalTokens = await tokenResponse.json();

  // Activate session with encrypted external tokens
  const updates = activateSession(session, {
    external: encryptToken(externalTokens), // implement your encryption
  });
  await sessionStore.update(sessionId, updates);

  // Generate plugin token
  const pluginToken = await generatePluginToken(
    sessionId,
    session.platformId,
    process.env.PLUGIN_SIGNING_KEY!
  );

  // Redirect back to platform
  const callbackUrl = new URL(session.platformCallback);
  callbackUrl.searchParams.set("token", pluginToken);
  callbackUrl.searchParams.set("state", platformState);

  return Response.redirect(callbackUrl.toString(), 302);
}
```

### 4. Handle Token Refresh (Optional)

```typescript
async function onToken(req: Request): Promise<Response> {
  const body = await req.text();
  const params = new URLSearchParams(body);
  const refreshToken = params.get("refresh_token")!;

  // Validate refresh token
  const { sessionId, platformId } = await validatePluginToken(
    refreshToken,
    process.env.PLUGIN_PUBLIC_KEY!
  );

  const session = await sessionStore.get(sessionId);
  if (!session || !isSessionValid(session)) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  // Optionally refresh external tokens here

  // Issue new tokens
  const newAccessToken = await generatePluginToken(
    sessionId,
    platformId,
    process.env.PLUGIN_SIGNING_KEY!,
    { expiresIn: "1h" }
  );
  const newRefreshToken = await generateRefreshToken(
    sessionId,
    platformId,
    process.env.PLUGIN_SIGNING_KEY!
  );

  return Response.json({
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    token_type: "Bearer",
    expires_in: 3600,
  });
}
```

## Request Binding (Anti-Replay Protection)

To prevent replay attacks and ensure platform identity, each MCP request must include a platform assertion.

### Platform Requirements

On each MCP request, the platform must include:

```http
POST /mcp HTTP/1.1
Authorization: Bearer <plugin_token>
X-Platform-Assertion: <platform_assertion_jwt>
Content-Type: application/json

{"jsonrpc":"2.0","method":"tools/call",...}
```

### Platform Assertion JWT

The platform signs a JWT with these claims:

```typescript
{
  iss: "https://platform.example.com",  // Platform identifier
  iat: 1706000000,                       // Issued at (must be within 30s)
  ath: "abc123...",                      // SHA-256 hash of plugin token (base64url)
  req_hash: "def456..."                  // SHA-256 hash of request (base64url)
}
```

The `req_hash` is computed as:
```
SHA-256(METHOD + "\n" + PATH + "\n" + BODY)
```

### Plugin Validation

```typescript
import { validateAuthenticatedRequest } from "@futuritywork/plugins";

app.middleware(async (req, next) => {
  try {
    const { session, platformId } = await validateAuthenticatedRequest(
      req,
      process.env.PLUGIN_PUBLIC_KEY!,
      "https://platform.example.com/.well-known/jwks.json",
      sessionStore,
      { assertionMaxAge: 30 } // seconds
    );

    // Session and platform verified - proceed with request
    // Access external tokens from session.externalTokens
    return next(req);
  } catch (error) {
    return Response.json(
      { error: "unauthorized", message: error.message },
      { status: 401 }
    );
  }
});
```

## Security Model

### Session Isolation

- Each session is bound to a specific platform (`platformId`)
- Plugin tokens include the platform ID (`pid` claim)
- Platform assertions must match the session's platform

### Replay Protection

| Protection | Mechanism |
|------------|-----------|
| Time-based | Assertion `iat` must be within 30 seconds |
| Token-bound | `ath` hash must match the plugin token |
| Request-bound | `req_hash` must match the HTTP request |
| Platform-bound | `iss` must match session's platform |

### Token Security

| Token | Signed By | Contains | Lifetime |
|-------|-----------|----------|----------|
| User Context JWT | Platform | user_id, platform_id | 60 seconds |
| Plugin Token | Plugin | session_id, platform_id | 1 hour |
| Refresh Token | Plugin | session_id, platform_id, type | 7 days |
| Platform Assertion | Platform | ath, req_hash | 30 seconds |

## Session Store Interface

Implement this interface for production use:

```typescript
interface SessionStore {
  create(session: PendingSession): Promise<void>;
  get(sessionId: string): Promise<Session | null>;
  update(sessionId: string, updates: Partial<Session>): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

interface Session {
  id: string;
  platformId: string;
  userId: string;
  organizationId?: string;
  email?: string;
  displayName?: string;
  state: "pending" | "active" | "expired" | "revoked";
  externalTokens?: Record<string, EncryptedToken>;
  platformState: string;
  platformCallback: string;
  createdAt: Date;
  expiresAt?: Date;
}
```

## Platform Integration Guide

### Discovery

Platforms discover plugin auth configuration from:

```
GET /.well-known/futurity/plugin
```

Response includes:
- `auth.type: "chained"` - indicates chained auth
- `auth.authorizationEndpoint` - where to redirect users
- `auth.requiredUserContext` - what user info to include in JWT

### Initiating Auth

```typescript
// Platform creates user context JWT
const userContextJwt = await new SignJWT({
  sub: user.id,
  email: user.email,
  org_id: user.organizationId,
})
  .setProtectedHeader({ alg: "RS256" })
  .setIssuer("https://platform.example.com")
  .setIssuedAt()
  .setExpirationTime("60s")
  .sign(platformPrivateKey);

// Redirect user to plugin
const authUrl = new URL(plugin.auth.authorizationEndpoint);
authUrl.searchParams.set("token", userContextJwt);
authUrl.searchParams.set("state", generateState());
authUrl.searchParams.set("redirect_uri", "https://platform.example.com/callback");

redirect(authUrl);
```

### Making MCP Requests

```typescript
// Create platform assertion
const tokenHash = await sha256Base64Url(pluginToken);
const requestHash = await sha256Base64Url(`POST\n/mcp\n${body}`);

const assertion = await new SignJWT({
  ath: tokenHash,
  req_hash: requestHash,
})
  .setProtectedHeader({ alg: "RS256" })
  .setIssuer("https://platform.example.com")
  .setIssuedAt()
  .sign(platformPrivateKey);

// Make request
const response = await fetch("https://plugin.example.com/mcp", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${pluginToken}`,
    "X-Platform-Assertion": assertion,
  },
  body,
});
```

### JWKS Endpoint

Platforms must serve their public keys at:

```
GET /.well-known/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "platform-key-1",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## Migration from Auth Forwarding (v1)

The v1 `authForwarding` format is still supported for backward compatibility:

```typescript
// v1 format (still works)
{
  specVersion: 1,
  authForwarding: {
    tokenEndpoint: "...",
    authorizationEndpoint: "...",
  }
}

// v2 format (recommended)
{
  specVersion: 2,
  auth: {
    type: "forwarding",  // or "chained"
    tokenEndpoint: "...",
    authorizationEndpoint: "...",
  }
}
```

The `PluginManifestSchemaCompat` automatically transforms v1 manifests to v2 format internally.
