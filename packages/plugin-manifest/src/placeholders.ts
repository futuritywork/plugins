export const PLACEHOLDER = /\{([^{}\s]+)\}/g;

/** The distinct `{fieldKey}` names in a text, in order of first use. */
export function placeholders(text: string): string[] {
  return [...new Set(Array.from(text.matchAll(PLACEHOLDER), (match) => match[1]!))];
}
