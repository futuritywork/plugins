import { cors, mcp, t } from "@futurity/plugins";
import type { PluginManifestOptions } from "@futurity/plugins";
import { forwardedAuth, requireAccessToken, tokenEndpoint } from "./auth";

const PORT = Number(process.env.PORT ?? 3000);

// Futurity reads the manifest and calls the tools from its own servers, so the
// URLs the manifest publishes must be the ones Futurity can reach.
const PUBLIC_URL = process.env.PUBLIC_URL ?? `http://localhost:${PORT}`;
const TOKEN_PATH = "/oauth/token";

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) {
  throw new Error(
    "FUTURITY_SIGNING_KEY is required to sign the plugin manifest.\n" +
      "Run `bun run keygen`, put the private key in .env, and restart to register this plugin.",
  );
}

const manifest: PluginManifestOptions = {
  pluginId: "{{slug}}",
  developerEmail: "developer@example.com", // Replace with your developer or support email.
  name: "{{name}}",
  version: "0.1.0",
  mcpUrl: `${PUBLIC_URL}/mcp`,
  auth: {
    type: "forwarding",
    grantType: "client_credentials",
    tokenEndpoint: `${PUBLIC_URL}${TOKEN_PATH}`,
    requiredScopes: [],
    deliveryMethod: "header",
  },
  signingKey,
};

const app = mcp({
  name: "{{slug}}",
  version: "0.1.0",
  pluginManifest: manifest,
});

app.use(cors()).middleware(tokenEndpoint(TOKEN_PATH)).middleware(forwardedAuth);

// A tool is a name, a description, an input schema, and a handler. The agent
// reads the description alone when it chooses a tool, so write it as *when to
// use this*, not as what it does internally.
app.tool("hello", {
  description: "Use when someone asks this plugin to greet a person by name.",
  input: t.obj({ name: t.str }),
  handler: async ({ name }) => ({ greeting: `Hello, ${name}!` }),
});

// Delete this one once your own tools call a real API. `requireAccessToken()`
// returns the credential Futurity forwarded for the caller.
app.tool("whoami", {
  description:
    "Use to prove the connection works. Returns the identity behind the forwarded credentials.",
  input: t.obj({}),
  handler: async () => {
    const token = requireAccessToken();
    // YOUR CODE HERE: call the system you wrap with this token.
    return { connected: true, tokenPreview: `${token.slice(0, 6)}…` };
  },
});

await app.listen(PORT);
