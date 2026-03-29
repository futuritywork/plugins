import { mcp, t } from "@futurity/plugins";

const app = mcp({
  name: "my-plugin",
  version: "0.1.0",
});

app.tool("hello", {
  description: "Say hello",
  input: t.obj({ name: t.str }),
  handler: async ({ name }) => ({
    greeting: `Hello, ${name}!`,
  }),
});

await app.listen(3000);
