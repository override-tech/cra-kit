import type { Hash, Scope } from "./model";

export interface Edge<K> {
  to: K;
  optional: boolean;
}

export interface Root<K> {
  to: K;
  kind: "required" | "optional" | "dev";
}

function reach<K>(starts: K[], edges: (node: K) => Edge<K>[], followOptional: boolean): Set<K> {
  const seen = new Set<K>(starts);
  const queue = [...starts];
  for (let node = queue.pop(); node !== undefined; node = queue.pop()) {
    for (const edge of edges(node)) {
      if ((followOptional || !edge.optional) && !seen.has(edge.to)) {
        seen.add(edge.to);
        queue.push(edge.to);
      }
    }
  }
  return seen;
}

/**
 * Scopes every node reachable from the roots: "required" when reachable from a
 * production root through non-optional edges only, "optional" when reachable
 * from production roots only through an optional edge, and "excluded" when
 * only development roots reach it. Unreachable nodes are absent.
 */
export function classify<K>(roots: Root<K>[], edges: (node: K) => Edge<K>[]): Map<K, Scope> {
  const required = reach(
    roots.filter((r) => r.kind === "required").map((r) => r.to),
    edges,
    false,
  );
  const production = reach(
    roots.filter((r) => r.kind !== "dev").map((r) => r.to),
    edges,
    true,
  );
  const dev = reach(
    roots.filter((r) => r.kind === "dev").map((r) => r.to),
    edges,
    true,
  );
  const scopes = new Map<K, Scope>();
  for (const node of dev) scopes.set(node, "excluded");
  for (const node of production) scopes.set(node, required.has(node) ? "required" : "optional");
  return scopes;
}

const ALGORITHMS: Record<string, Hash["alg"]> = {
  sha1: "SHA-1",
  sha256: "SHA-256",
  sha512: "SHA-512",
};

/** Subresource-integrity strings ("sha512-<base64> sha1-<base64>") to CycloneDX hex hashes. */
export function integrityHashes(integrity: unknown): Hash[] {
  if (typeof integrity !== "string") return [];
  const hashes: Hash[] = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf("-");
    const alg = ALGORITHMS[token.slice(0, dash).toLowerCase()];
    if (!alg || hashes.some((h) => h.alg === alg)) continue;
    const content = Buffer.from(token.slice(dash + 1), "base64").toString("hex");
    if (content) hashes.push({ alg, content });
  }
  return hashes;
}

/** License strings from manifests (`"MIT"`, `{type: "MIT"}`, `["MIT", "GPL-2.0"]`). */
export function licenseStrings(value: unknown): string[] {
  if (typeof value === "string") return value.trim() ? [value.trim()] : [];
  if (Array.isArray(value)) return value.flatMap(licenseStrings);
  if (value && typeof value === "object" && "type" in value) return licenseStrings(value.type);
  return [];
}
