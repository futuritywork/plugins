import { FUTURITY_META_KEY, mcp, t, type PluginManifestInput } from "@futurity/plugins";

const PORT = Number(process.env.PORT ?? 3000);

// Futurity reads the manifest and calls the tools from its own servers, so the
// URLs the manifest publishes must be the ones Futurity can reach.
const PUBLIC_URL = process.env.PUBLIC_URL ?? `http://localhost:${PORT}`;
const FUTURITY_URL = process.env.FUTURITY_URL ?? "https://api-v4.futurity.work";

const manifest: PluginManifestInput = {
  name: "com.example/{{slug}}", // Replace com.example with a domain you own, reversed.
  title: "{{name}}",
  description: "Describe what this plugin connects Futurity to.",
  version: "0.1.0",
  remotes: [{ type: "streamable-http", url: `${PUBLIC_URL}/mcp` }],
  _meta: {
    [FUTURITY_META_KEY]: {
      specVersion: 5,
      developer: { email: "developer@example.com" }, // Replace with your developer or support email.
      credentials: [
        {
          id: "api-key",
          label: "Organization API key",
          holder: "org",
          method: { type: "secrets" },
          fields: [
            {
              key: "api_key",
              label: "API key",
              kind: "plugin_secret",
              scope: "install",
              input: "password",
              header: "X-Api-Key",
            },
          ],
        },
      ],
    },
  },
};

const app = mcp({
  manifest,
  futurity: { issuers: [{ issuer: FUTURITY_URL, jwksUrl: `${FUTURITY_URL}/oauth/jwks` }] },
});

// A tool is a name, a description, an input schema, an output schema, and a
// handler. The agent reads the description alone when it chooses a tool, so
// write it as *when to use this*, not as what it does internally. The output
// schema is required: it tells Futurity what the tool returns.
app.tool("hello", {
  description: "Use when someone asks this plugin to greet a person by name.",
  input: t.obj({ name: t.str }),
  output: t.obj({ greeting: t.str }),
  annotations: { readOnlyHint: true },
  handler: async ({ name }) => ({ greeting: `Hello, ${name}!` }),
});

// Delete this one once your own tools call a real API. The context carries the
// verified caller and the credentials Futurity delivered for them.
app.tool("whoami", {
  description: "Use to prove the connection works. Returns who Futurity says is calling.",
  output: t.obj({ org: t.str, user: t.str, keyPreview: t.str }),
  annotations: { readOnlyHint: true },
  handler: async (_input, { org, user, credentials }) => {
    // YOUR CODE HERE: call the system you wrap with credentials.api_key.
    return { org: org.id, user: user.id, keyPreview: `${credentials.api_key?.slice(0, 4)}...` };
  },
});

await app.listen(PORT);
