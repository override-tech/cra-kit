import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, posix } from "node:path";
import { CliError, errnoCode } from "../../errors";
import { compareStrings } from "../../format";
import { classify, type Edge, type Root } from "../graph";
import type { Component, Ecosystem, Hash, LockfileResult } from "../model";
import { makePurl } from "../purl";

export interface LockContext {
  /** Project-relative POSIX path of the lockfile, used in messages and SBOM properties. */
  file: string;
  /** Absolute directory holding the lockfile; manifests are read relative to it. */
  dir: string;
  includeDev: boolean;
  /** Workspace package (POSIX path relative to `dir`) to restrict to; null means every one. */
  importer: string | null;
}

export class LockfileError extends CliError {}

export interface PackageNode {
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  licenses?: string[];
  hashes?: Hash[];
}

/** Reads a manifest next to the lockfile; null when it does not exist. */
export function readSibling(ctx: LockContext, relativePath: string): string | null {
  try {
    return readFileSync(join(ctx.dir, relativePath), "utf8");
  } catch (error) {
    const code = errnoCode(error);
    if (code === "ENOENT" || code === "ENOTDIR" || code === "EISDIR") return null;
    throw error;
  }
}

export function parseJson(text: string, file: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new LockfileError(`${file} is not valid JSON: ${String(error)}`);
  }
}

/**
 * Expands workspace globs ("packages/*", "apps/**", "tools/cli") to directories
 * relative to `dir` that contain `marker` (package.json, Cargo.toml).
 */
export function expandWorkspaces(dir: string, patterns: string[], marker: string): string[] {
  const out = new Set<string>();
  const walk = (base: string, segments: string[]) => {
    if (segments.length === 0) {
      if (statSafe(join(dir, base, marker))?.isFile()) out.add(base === "" ? "." : base);
      return;
    }
    const [head, ...rest] = segments as [string, ...string[]];
    if (head === "**") {
      walk(base, rest);
      for (const child of childDirs(join(dir, base))) walk(posix.join(base, child), segments);
    } else if (head.includes("*")) {
      const re = new RegExp(
        `^${head.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`,
      );
      for (const child of childDirs(join(dir, base))) {
        if (re.test(child)) walk(posix.join(base, child), rest);
      }
    } else {
      walk(posix.join(base, head), rest);
    }
  };
  for (const pattern of patterns) {
    if (pattern.startsWith("!")) continue;
    walk("", pattern.replace(/^\.\//, "").split("/").filter(Boolean));
  }
  return [...out].sort(compareStrings);
}

function statSafe(path: string) {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

function childDirs(path: string): string[] {
  try {
    return readdirSync(path, { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name !== "node_modules" && !d.name.startsWith("."))
      .map((d) => d.name);
  } catch {
    return [];
  }
}

/**
 * Turns a lockfile graph into SBOM components. `packages` holds only nodes
 * that are third-party packages; any other node reachable through `edges`
 * (workspace members, links) is internal to the product and traversed through.
 */
export function finalize<K>(
  ctx: LockContext,
  input: {
    packages: Map<K, PackageNode>;
    roots: Root<K>[];
    edges: (node: K) => Edge<K>[];
    graphKnown: boolean;
    warnings?: string[];
    /** Direct dependencies, when they differ from the non-dev roots. */
    direct?: K[];
  },
): LockfileResult {
  const { packages, roots, edges } = input;
  const scopes = classify(roots, edges);
  const purls = new Map<K, string>();
  for (const [key, node] of packages) {
    const scope = scopes.get(key);
    if (scope === undefined || (scope === "excluded" && !ctx.includeDev)) continue;
    purls.set(key, makePurl(node.ecosystem, node.name, node.version));
  }

  // Dependencies seen through internal nodes (workspace members) are flattened.
  const packageTargets = (starts: K[]): string[] => {
    const found = new Set<string>();
    const seen = new Set<K>();
    const queue = [...starts];
    for (let node = queue.pop(); node !== undefined; node = queue.pop()) {
      if (seen.has(node)) continue;
      seen.add(node);
      const purl = purls.get(node);
      if (purl !== undefined) found.add(purl);
      else if (!packages.has(node)) queue.push(...edges(node).map((e) => e.to));
    }
    return [...found].sort(compareStrings);
  };

  const components: Component[] = [];
  for (const [key, purl] of purls) {
    const node = packages.get(key);
    const scope = scopes.get(key);
    if (!node || !scope) continue;
    components.push({
      purl,
      ecosystem: node.ecosystem,
      name: node.name,
      version: node.version,
      scope,
      licenses: node.licenses ?? [],
      hashes: node.hashes ?? [],
      dependsOn: input.graphKnown ? packageTargets(edges(key).map((e) => e.to)) : [],
      graphKnown: input.graphKnown,
      sources: [ctx.file],
    });
  }
  const directRoots =
    input.direct ?? roots.filter((r) => r.kind !== "dev" || ctx.includeDev).map((r) => r.to);
  return {
    file: ctx.file,
    components,
    direct: packageTargets(directRoots),
    warnings: input.warnings ?? [],
  };
}
