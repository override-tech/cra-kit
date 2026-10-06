import { compareStrings } from "../format";

export type Ecosystem = "npm" | "pypi" | "golang" | "cargo" | "composer";
/** CycloneDX component scope; dev-only dependencies are "excluded". */
export type Scope = "required" | "optional" | "excluded";

export interface Hash {
  alg: "SHA-1" | "SHA-256" | "SHA-512";
  content: string;
}

export interface Component {
  /** Package URL; doubles as the CycloneDX bom-ref. */
  purl: string;
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  scope: Scope;
  licenses: string[];
  hashes: Hash[];
  /** purls of dependencies, when the lockfile records the graph. */
  dependsOn: string[];
  /** Whether `dependsOn` is known (lockfiles without a graph leave it empty). */
  graphKnown: boolean;
  /** Lockfiles (project-relative, POSIX separators) the component came from. */
  sources: string[];
}

export interface LockfileResult {
  file: string;
  components: Component[];
  /** purls the product depends on directly. */
  direct: string[];
  warnings: string[];
}

export interface Inventory {
  components: Component[];
  direct: string[];
  lockfiles: string[];
  warnings: string[];
}

const SCOPE_RANK: Record<Scope, number> = { required: 0, optional: 1, excluded: 2 };

const sortedUnion = (a: string[], b: string[]) => [...new Set([...a, ...b])].sort(compareStrings);

/** Merges components that share a purl (same package seen in several places or lockfiles). */
export function mergeComponents(components: Component[]): Component[] {
  const byPurl = new Map<string, Component>();
  for (const c of components) {
    const seen = byPurl.get(c.purl);
    if (!seen) {
      byPurl.set(c.purl, {
        ...c,
        licenses: [...new Set(c.licenses)],
        dependsOn: sortedUnion(c.dependsOn, []),
        sources: sortedUnion(c.sources, []),
      });
      continue;
    }
    if (SCOPE_RANK[c.scope] < SCOPE_RANK[seen.scope]) seen.scope = c.scope;
    for (const license of c.licenses) {
      if (!seen.licenses.includes(license)) seen.licenses.push(license);
    }
    for (const hash of c.hashes) {
      if (!seen.hashes.some((h) => h.alg === hash.alg)) seen.hashes.push(hash);
    }
    seen.dependsOn = sortedUnion(seen.dependsOn, c.dependsOn);
    seen.graphKnown ||= c.graphKnown;
    seen.sources = sortedUnion(seen.sources, c.sources);
  }
  return [...byPurl.values()]
    .map((c) => ({
      ...c,
      hashes: [...c.hashes].sort((a, b) => compareStrings(a.alg, b.alg)),
      dependsOn: c.dependsOn.filter((d) => d !== c.purl && byPurl.has(d)),
    }))
    .sort((a, b) => compareStrings(a.purl, b.purl));
}

export function mergeResults(results: LockfileResult[]): Inventory {
  const components = mergeComponents(results.flatMap((r) => r.components));
  const known = new Set(components.map((c) => c.purl));
  return {
    components,
    direct: [...new Set(results.flatMap((r) => r.direct))]
      .filter((p) => known.has(p))
      .sort(compareStrings),
    lockfiles: results.map((r) => r.file).sort(compareStrings),
    warnings: results.flatMap((r) => r.warnings.map((w) => `${r.file}: ${w}`)),
  };
}
