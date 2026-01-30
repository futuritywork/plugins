# Migration Guide: Auth Forwarding (v1) to Chained Auth (v2)

This guide covers migrating from v1 auth forwarding to v2 chained OAuth authentication.

## When to Migrate

**Stay on v1 (Auth Forwarding)** if:
- You only need a single OAuth provider
- You don't need to store tokens between requests
- The platform can manage token refresh for you
- Simplicity is more important than control

**Migrate to v2 (Chained Auth)** if:
- You need to integrate with multiple external services
- You need persistent sessions with stored tokens
- You need control over token refresh logic
- You need to associate user data with sessions

## Overview of Changes

| Aspect | v1 (Auth Forwarding) | v2 (Chained Auth) |
|--------|---------------------|-------------------|
| Token management | Platform | Plugin |
| Session storage | None | Required |
| OAuth flow | Platform handles | Plugin handles |
| Request auth | Bearer token only | Token + platform assertion |
| Manifest auth type | `"forwarding"` | `"chained"` |

## Step-by-Step Migration

### 1. Update Plugin Manifest

**Before (v1):**
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
      type: "forwarding",
      tokenEndpoint: "https://external.com/oauth/token",
      authorizationEndpoint: "https://external.com/oauth/authorize",
      requiredScopes: ["read", "write"],
      deliveryMethod: "header",
    },
    mcpUrl: "https://plugin.example.com/mcp",
  },
  auth: async (req) => {
    const token = req.headers.get("authorization")?.slice(7);
    return !!token;
  },
});
```

**After (v2):**
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
      requiredUserContext: ["user_id", "email"],
      externalServices: [
        {
          name: "External Service",
          authorizationEndpoint: "https://external.com/oauth/authorize",
          requiredScopes: ["read", "write"],
        },
      ],
    },
    mcpUrl: "https://plugin.example.com/mcp",
  },
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

### 2. Add Session Storage

v2 requires a session store. For development, use the built-in in-memory store:

```typescript
import { InMemorySessionStore } from "@futuritywork/plugins";

const sessionStore = new InMemorySessionStore();
```

For production, implement the `SessionStore` interface with your database:

```typescript
import type { SessionStore, Session, PendingSession } from "@futuritywork/plugins";

class PostgresSessionStore implements SessionStore {
  async create(session: PendingSession): Promise<void> {
    await db.query(
      `INSERT INTO sessions (id, platform_id, user_id, state, platform_state, platform_callback, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [session.id, session.platformId, session.userId, session.state,
       session.platformState, session.platformCallback, session.createdAt]
    );
  }

  async get(sessionId: string): Promise<Session | null> {
    const result = await db.query(`SELECT * FROM sessions WHERE id = $1`, [sessionId]);
    return result.rows[0] ?? null;
  }

  async update(sessionId: string, updates: Partial<Session>): Promise<void> {
    // Build UPDATE query from updates object
  }

  async delete(sessionId: string): Promise<void> {
    await db.query(`DELETE FROM sessions WHERE id = $1`, [sessionId]);
  }
}
```

### 3. Implement OAuth Handlers

**Authorization handler** - creates a pending session and redirects to external OAuth:

```typescript
import {
  createPendingSession,
  generateChainedState,
  type UserContext,
} from "@futuritywork/plugins";

async function onAuthorize(
  userContext: UserContext,
  platformState: string,
  platformCallback: string
): Promise<Response> {
  // Create pending session from platform-provided user context
  const session = createPendingSession(userContext, platformState, platformCallback);
  await sessionStore.create(session);

  // Chain state parameters (preserves platform state + adds session ID)
  const chainedState = generateChainedState(platformState, session.id);

  // Redirect to external OAuth (this replaces what the platform used to do)
  const authUrl = new URL("https://external.com/oauth/authorize");
  authUrl.searchParams.set("client_id", process.env.EXTERNAL_CLIENT_ID!);
  authUrl.searchParams.set("redirect_uri", "https://plugin.example.com/auth/callback");
  authUrl.searchParams.set("state", chainedState);
  authUrl.searchParams.set("scope", "read write");
  authUrl.searchParams.set("response_type", "code");

  return Response.redirect(authUrl.toString(), 302);
}
```

**Callback handler** - exchanges code for tokens, activates session, returns plugin token:

```typescript
import {
  parseChainedState,
  activateSession,
  generatePluginToken,
} from "@futuritywork/plugins";

async function onCallback(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error || !code || !state) {
    return new Response(`OAuth error: ${error ?? "missing parameters"}`, { status: 400 });
  }

  // Parse chained state to get session ID
  const { platform: platformState, session: sessionId } = parseChainedState(state);

  // Retrieve pending session
  const session = await sessionStore.get(sessionId);
  if (!session || session.state !== "pending") {
    return new Response("Invalid or expired session", { status: 400 });
  }

  // Exchange code for external tokens (this is now YOUR responsibility)
  const tokenResponse = await fetch("https://external.com/oauth/token", {
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

  if (!tokenResponse.ok) {
    return new Response("Token exchange failed", { status: 502 });
  }

  const externalTokens = await tokenResponse.json();

  // Activate session and store encrypted tokens
  const updates = activateSession(session, {
    external: await encryptToken(externalTokens), // implement encryption
  });
  await sessionStore.update(sessionId, updates);

  // Generate plugin token (platform will use this for MCP requests)
  const pluginToken = await generatePluginToken(
    sessionId,
    session.platformId,
    process.env.PLUGIN_SIGNING_KEY!,
    { expiresIn: "1h" }
  );

  // Redirect back to platform with token
  const callbackUrl = new URL(session.platformCallback);
  callbackUrl.searchParams.set("token", pluginToken);
  callbackUrl.searchParams.set("state", platformState);

  return Response.redirect(callbackUrl.toString(), 302);
}
```

### 4. Update Request Authentication

**Before (v1)** - simple token extraction:

```typescript
auth: async (req) => {
  const token = req.headers.get("authorization")?.slice(7);
  if (!token) return false;

  // Use forwarded token directly with external API
  const client = new ExternalClient({ token });
  await client.validateToken();
  return true;
}
```

**After (v2)** - validate plugin token + platform assertion, then use stored tokens:

```typescript
import { validateAuthenticatedRequest } from "@futuritywork/plugins";

// The chainedAuth config handles this automatically, but you can add custom logic:
app.middleware(async (req, next) => {
  // validateAuthenticatedRequest is called automatically by chainedAuth
  // Access session from request context if you need it:
  const session = req.session; // if you've set this up

  // Use stored external tokens for API calls
  const externalToken = await decryptToken(session.externalTokens?.external);
  const client = new ExternalClient({ token: externalToken.access_token });

  return next(req);
});
```

### 5. Handle Token Refresh (Optional)

If you want to support token refresh:

```typescript
import { validatePluginToken, generatePluginToken, generateRefreshToken, isSessionValid } from "@futuritywork/plugins";

async function onToken(req: Request): Promise<Response> {
  const body = await req.text();
  const params = new URLSearchParams(body);
  const grantType = params.get("grant_type");
  const refreshToken = params.get("refresh_token");

  if (grantType !== "refresh_token" || !refreshToken) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  // Validate the refresh token
  let payload;
  try {
    payload = await validatePluginToken(refreshToken, process.env.PLUGIN_PUBLIC_KEY!);
  } catch {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  const session = await sessionStore.get(payload.sessionId);
  if (!session || !isSessionValid(session)) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  // Optionally refresh external tokens if they're expired
  // ...

  // Issue new plugin tokens
  const newAccessToken = await generatePluginToken(
    session.id,
    session.platformId,
    process.env.PLUGIN_SIGNING_KEY!,
    { expiresIn: "1h" }
  );
  const newRefreshToken = await generateRefreshToken(
    session.id,
    session.platformId,
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

## Environment Variables

**Before (v1):**
```bash
PLUGIN_SIGNING_KEY=...  # For manifest signing only
```

**After (v2):**
```bash
PLUGIN_SIGNING_KEY=...       # For manifest + token signing
PLUGIN_PUBLIC_KEY=...        # For token validation (derive from signing key)
EXTERNAL_CLIENT_ID=...       # OAuth client ID (you manage this now)
EXTERNAL_CLIENT_SECRET=...   # OAuth client secret
TOKEN_ENCRYPTION_KEY=...     # For encrypting stored tokens
```

## Database Schema

If using a database for sessions, here's a sample schema:

```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  platform_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  organization_id TEXT,
  email TEXT,
  display_name TEXT,
  state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'expired', 'revoked')),
  external_tokens JSONB,  -- encrypted
  platform_state TEXT NOT NULL,
  platform_callback TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_platform_id ON sessions(platform_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_state ON sessions(state);
```

## Security Considerations

### Token Encryption

External tokens stored in sessions should be encrypted:

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const ALGORITHM = "aes-256-gcm";
const KEY = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY!, "base64");

async function encryptToken(data: unknown): Promise<string> {
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

async function decryptToken(encrypted: string): Promise<unknown> {
  const data = Buffer.from(encrypted, "base64");
  const iv = data.subarray(0, 16);
  const authTag = data.subarray(16, 32);
  const ciphertext = data.subarray(32);
  const decipher = createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}
```

### Platform Assertion Validation

v2 requires the platform to sign assertions for each request. This prevents:
- Replay attacks (assertions expire in 30 seconds)
- Token theft (assertion is bound to specific token hash)
- Request tampering (assertion includes request hash)

The `chainedAuth` config handles this automatically.

## Checklist

- [ ] Update manifest `auth.type` from `"forwarding"` to `"chained"`
- [ ] Add `authorizationEndpoint` and `callbackEndpoint` to manifest
- [ ] Implement session store (or use `InMemorySessionStore` for dev)
- [ ] Implement `onAuthorize` handler
- [ ] Implement `onCallback` handler
- [ ] Add `EXTERNAL_CLIENT_ID` and `EXTERNAL_CLIENT_SECRET` env vars
- [ ] Set up token encryption for stored external tokens
- [ ] (Optional) Implement `onToken` handler for refresh
- [ ] Test the full OAuth flow end-to-end
- [ ] Coordinate with platform team for assertion support

## Rollback

If you need to rollback, simply revert manifest changes to `auth.type: "forwarding"` and restore the `auth` middleware. Session data will be orphaned but the platform will resume token management.

## Platform Coordination

The platform team needs to:

1. **Detect chained auth** from your manifest (`auth.type: "chained"`)
2. **Create user context JWTs** with required claims when redirecting users
3. **Include platform assertions** on all MCP requests
4. **Serve JWKS endpoint** at `/.well-known/jwks.json`

See [chained-auth.md](./chained-auth.md#platform-integration-guide) for platform implementation details.
