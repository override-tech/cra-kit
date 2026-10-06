/** Narrowing helpers for parsed JSON, YAML and TOML (config files, lockfiles, API responses). */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isOneOf<T extends string>(options: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (options as readonly string[]).includes(value);
}

/** The value as a record, or an empty one when it is anything else. */
export function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

/** The value as an array, or an empty one when it is anything else. */
export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** A `{ name: versionOrRange }` map with non-string values dropped. */
export function asStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, v] of Object.entries(asRecord(value))) {
    if (typeof v === "string") out[key] = v;
  }
  return out;
}
