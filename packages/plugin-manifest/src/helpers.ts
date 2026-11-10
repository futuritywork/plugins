import { FUTURITY_META_KEY, type CredentialField, type CredentialOption, type FuturityExtension, type PluginManifest } from "./schema";

export type ToolDanger = "read" | "write" | "delete";

export type DangerAnnotations = { readOnlyHint?: boolean; destructiveHint?: boolean };

export function futurityExtension(manifest: PluginManifest): FuturityExtension {
  return manifest._meta[FUTURITY_META_KEY];
}

/** An org admin must install the option before anyone can use it. */
export function installRequired(option: CredentialOption): boolean {
  return option.fields.some((field) => field.scope === "install") || (option.method.type === "oauth" && option.method.client === "install");
}

export function fieldsFor(option: CredentialOption, scope: CredentialField["scope"]): CredentialField[] {
  return option.fields.filter((field) => field.scope === scope);
}

/** A tool marked both ways is treated as the riskier one. */
export function toolDanger(annotations: DangerAnnotations | undefined): ToolDanger {
  if (annotations?.destructiveHint === true) return "delete";
  if (annotations?.readOnlyHint === true) return "read";
  return "write";
}
