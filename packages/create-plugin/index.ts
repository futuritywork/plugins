#!/usr/bin/env bun
import { existsSync, mkdirSync, cpSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve, basename } from "node:path";
import { execSync } from "node:child_process";

const arg = process.argv[2];

if (!arg) {
  console.error("Usage: bun create futurity-plugin <project-name>");
  console.error("       bun create futurity-plugin .  (scaffold in current directory)");
  process.exit(1);
}

const isCwd = arg === ".";
const targetDir = isCwd ? process.cwd() : resolve(process.cwd(), arg);
const projectName = isCwd ? basename(process.cwd()) : arg;

if (!isCwd) {
  if (existsSync(targetDir)) {
    console.error(`Error: Directory "${arg}" already exists.`);
    process.exit(1);
  }
  mkdirSync(targetDir, { recursive: true });
}

// Copy template files
const templateDir = resolve(import.meta.dirname, "template");
cpSync(templateDir, targetDir, { recursive: true });

// Process package.json template
const pkgPath = resolve(targetDir, "package.json.tmpl");
const pkgContent = readFileSync(pkgPath, "utf-8");
writeFileSync(
  resolve(targetDir, "package.json"),
  pkgContent.replace(/\{\{name\}\}/g, projectName)
);
unlinkSync(pkgPath);

// Install dependencies
console.log(`\nScaffolding ${projectName}...\n`);
execSync("bun install", { cwd: targetDir, stdio: "inherit" });

console.log(`\n✅ Created ${projectName}\n`);
console.log("Next steps:\n");
if (!isCwd) {
  console.log(`  cd ${arg}`);
}
console.log("  bun run src/index.ts\n");
