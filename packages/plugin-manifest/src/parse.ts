import type { z } from "zod";
import { DevelopmentPluginManifestSchema, PluginManifestSchema, type PluginManifest } from "./schema";

export type ParseManifestOptions = { development?: boolean };

export type ParseManifestResult = { success: true; manifest: PluginManifest } | { success: false; errors: string[] };

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** Renders a zod path as `_meta["work.futurity/plugin"].credentials[0].fields[1].header`. */
function formatPath(path: PropertyKey[]): string {
  let text = "";
  for (const segment of path) {
    if (typeof segment === "number") text += `[${segment}]`;
    else if (typeof segment === "string" && IDENTIFIER.test(segment)) text += text ? `.${segment}` : segment;
    else text += `[${JSON.stringify(String(segment))}]`;
  }
  return text || "(root)";
}

function formatIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${formatPath(issue.path)}: ${issue.message}`);
}

/** Validates a manifest, given as JSON text or an already parsed value, against every spec 5 rule. */
export function parsePluginManifest(json: unknown, options: ParseManifestOptions = {}): ParseManifestResult {
  let value = json;
  if (typeof json === "string") {
    try {
      value = JSON.parse(json);
    } catch (error) {
      return { success: false, errors: [`(root): not valid JSON: ${(error as Error).message}`] };
    }
  }
  const schema = options.development ? DevelopmentPluginManifestSchema : PluginManifestSchema;
  const result = schema.safeParse(value);
  return result.success ? { success: true, manifest: result.data } : { success: false, errors: formatIssues(result.error) };
}
