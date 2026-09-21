import { $ } from "bun";

// Clean dist
await $`rm -rf dist`;

// Build JS with bun (fast, handles all TS)
const entrypoints = [
  "src/index.ts",
  "src/signing.ts",
  "src/cors.ts",
  "src/oauth.ts",
];

await Bun.build({
  entrypoints,
  outdir: "./dist",
  target: "bun",
  format: "esm",
  splitting: true,
  external: [
    "@modelcontextprotocol/sdk",
    "zod",
    "jose",
  ],
});

// Generate .d.ts with tsc
await $`tsc --declaration --emitDeclarationOnly --outDir dist --project tsconfig.build.json`;

console.log("Build complete → dist/");
