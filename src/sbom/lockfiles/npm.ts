import { posix } from "node:path";
import { asRecord, asString, asStringMap } from "../../guards";
import { type Edge, integrityHashes, licenseStrings, type Root } from "../graph";
import type { LockfileResult } from "../model";
import { finalize, type LockContext, LockfileError, type PackageNode, parseJson } from "./shared";

/**
 * npm package-lock.json / npm-shrinkwrap.json, lockfileVersion 2 and 3: the
 * flat `packages` map keyed by install path ("node_modules/a/node_modules/b").
 * Workspace folders are keys without a node_modules segment; `link` entries
 * point node_modules/<name> at them.
 */
export function parseNpmLock(text: string, ctx: LockContext): LockfileResult {
  const lock = asRecord(parseJson(text, ctx.file));
  const version = lock.lockfileVersion;
  if (lock.packages === undefined) {
    throw new LockfileError(
      `${ctx.file}: lockfileVersion ${String(version)} is not supported; regenerate it with npm 7 or newer (lockfileVersion 2 or 3)`,
    );
  }
  const entries = asRecord(lock.packages);
  const entry = (path: string) => asRecord(entries[path]);
  const isInstalled = (path: string) => path === "node_modules" || path.includes("node_modules/");

  /** Node's resolution: nearest node_modules/<name> walking up from `from`. */
  const resolve = (from: string, name: string): string | null => {
    let base = from;
    for (;;) {
      const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
      if (entries[candidate] !== undefined) return candidate;
      if (!base) return null;
      const nested = base.lastIndexOf("/node_modules/");
      base = nested >= 0 ? base.slice(0, nested) : "";
    }
  };

  const packages = new Map<string, PackageNode>();
  const warnings: string[] = [];
  for (const path of Object.keys(entries)) {
    const e = entry(path);
    if (!isInstalled(path) || e.link === true) continue;
    const name = asString(e.name) ?? path.slice(path.lastIndexOf("node_modules/") + 13);
    const v = asString(e.version);
    if (!v) warnings.push(`${path} has no version`);
    packages.set(path, {
      ecosystem: "npm",
      name,
      version: v ?? null,
      licenses: licenseStrings(e.license),
      hashes: integrityHashes(e.integrity),
    });
  }

  const edges = (path: string): Edge<string>[] => {
    const e = entry(path);
    if (e.link === true) {
      const target = asString(e.resolved);
      return target !== undefined && entries[target] !== undefined
        ? [{ to: target, optional: false }]
        : [];
    }
    const optionalPeers = asRecord(e.peerDependenciesMeta);
    const out: Edge<string>[] = [];
    const add = (deps: unknown, optional: (name: string) => boolean) => {
      for (const name of Object.keys(asStringMap(deps))) {
        const to = resolve(path, name);
        if (to !== null) out.push({ to, optional: optional(name) });
      }
    };
    add(e.dependencies, () => false);
    add(e.optionalDependencies, () => true);
    add(e.peerDependencies, (name) => asRecord(optionalPeers[name]).optional === true);
    return out;
  };

  const workspaces = Object.keys(entries).filter((p) => p !== "" && !isInstalled(p));
  let importers: string[];
  if (ctx.importer === null) {
    importers = ["", ...workspaces];
  } else {
    const wanted = ctx.importer === "." ? "" : posix.normalize(ctx.importer);
    if (entries[wanted] === undefined) {
      throw new LockfileError(`${ctx.file} has no workspace package at ${ctx.importer}`);
    }
    importers = [wanted];
  }
  const roots: Root<string>[] = [];
  for (const importer of importers) {
    const e = entry(importer);
    const add = (deps: unknown, kind: Root<string>["kind"]) => {
      for (const name of Object.keys(asStringMap(deps))) {
        const to = resolve(importer, name);
        if (to !== null) roots.push({ to, kind });
      }
    };
    add(e.dependencies, "required");
    add(e.peerDependencies, "required");
    add(e.optionalDependencies, "optional");
    add(e.devDependencies, "dev");
  }

  return finalize(ctx, { packages, roots, edges, graphKnown: true, warnings });
}
