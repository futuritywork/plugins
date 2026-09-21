#!/usr/bin/env bun
import { execSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";

const arg = process.argv[2];

if (!arg) {
  console.error("Usage: bunx create-futurity-plugin@latest <project-name>");
  console.error("       bunx create-futurity-plugin@latest .  (scaffold in current directory)");
  process.exit(1);
}

const isCwd = arg === ".";
const targetDir = isCwd ? process.cwd() : resolve(process.cwd(), arg);
const projectName = isCwd ? basename(process.cwd()) : arg;

/** A plugin id is a URL-safe slug, so it is derived rather than asked for. */
const slug =
  projectName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "my-plugin";

if (!isCwd) {
  if (existsSync(targetDir)) {
    console.error(`Error: Directory "${arg}" already exists.`);
    process.exit(1);
  }
  mkdirSync(targetDir, { recursive: true });
}

const templateDir = resolve(import.meta.dirname, "template");
cpSync(templateDir, targetDir, { recursive: true });

// npm strips a .gitignore from a published tarball and never unpacks a .env
// file, so both ship under a plain name and are restored here.
const renames: [from: string, to: string][] = [
  ["package.json.tmpl", "package.json"],
  ["_gitignore", ".gitignore"],
  ["env.example", ".env.example"],
];
for (const [from, to] of renames) {
  const source = join(targetDir, from);
  if (existsSync(source)) renameSync(source, join(targetDir, to));
}

const TEXT_FILE = /\.(ts|json|md|example)$|^\.(gitignore|env\.example)$/;

function fillPlaceholders(dir: string) {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules") continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      fillPlaceholders(path);
      continue;
    }
    if (!TEXT_FILE.test(entry)) continue;

    const content = readFileSync(path, "utf-8");
    if (!content.includes("{{")) continue;
    writeFileSync(
      path,
      content.replace(/\{\{name\}\}/g, projectName).replace(/\{\{slug\}\}/g, slug),
    );
  }
}
fillPlaceholders(targetDir);

console.log(`\nScaffolding ${projectName}...\n`);
execSync("bun install", { cwd: targetDir, stdio: "inherit" });

console.log(`\n✅ Created ${projectName}\n`);
console.log("Next steps:\n");
if (!isCwd) console.log(`  cd ${arg}`);
console.log("  cp .env.example .env");
console.log("  bun run keygen          # put the private key in .env");
console.log("  bun run dev             # serves on :3000\n");
console.log("Then write your tools in src/index.ts, and exchange your own");
console.log("credentials in the token endpoint in src/auth.ts.\n");
