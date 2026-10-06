import { posix } from "node:path";
import { parse } from "yaml";
import { asRecord, asString } from "../../guards";
import { type Edge, integrityHashes, type Root } from "../graph";
import type { LockfileResult } from "../model";
import { finalize, type LockContext, LockfileError, type PackageNode } from "./shared";

/** "@scope/name@1.2.3(peer@4.5.6)" -> name and version, peers stripped. */
export function splitPnpmKey(key: string): { name: string; version: string } | null {
  const paren = key.indexOf("(");
  const base = paren >= 0 ? key.slice(0, paren) : key;
  const at = base.indexOf("@", 1);
  if (at <= 0) return null;
  return { name: base.slice(0, at), version: base.slice(at + 1) };
}

const IMPORTER_PREFIX = "importer:";

/**
 * pnpm-lock.yaml v9: `importers` (workspace packages and their direct
 * dependencies), `packages` (metadata per name@version) and `snapshots`
 * (resolved dependency graph per name@version(peers)).
 */
export function parsePnpmLock(text: string, ctx: LockContext): LockfileResult {
  let doc: Record<string, unknown>;
  try {
    doc = asRecord(parse(text, { uniqueKeys: false }));
  } catch (error) {
    throw new LockfileError(`${ctx.file} is not valid YAML: ${String(error)}`);
  }
  const lockVersion = Number.parseFloat(String(doc.lockfileVersion ?? ""));
  if (!(lockVersion >= 9)) {
    throw new LockfileError(
      `${ctx.file}: lockfileVersion ${String(doc.lockfileVersion)} is not supported; upgrade to pnpm 9 or newer (lockfileVersion 9.0)`,
    );
  }
  const importers = asRecord(doc.importers);
  const meta = asRecord(doc.packages);
  // A lockfile without snapshots (no dependencies with peers) keys the graph by package.
  const snapshots = doc.snapshots === undefined ? meta : asRecord(doc.snapshots);

  /** A dependency reference ("1.2.3(peer@1)", "link:../core", "real-name@1.0.0") to a node. */
  const resolveRef = (name: string, ref: string, fromImporter: string | null): string | null => {
    if (ref.startsWith("link:")) {
      if (fromImporter === null) return null;
      const target = posix.normalize(posix.join(fromImporter, ref.slice(5)));
      return importers[target] !== undefined ? `${IMPORTER_PREFIX}${target}` : null;
    }
    for (const key of [`${name}@${ref}`, ref]) {
      if (snapshots[key] !== undefined) return key;
    }
    return null;
  };

  const importerDeps = (importer: string, field: string) =>
    Object.entries(asRecord(asRecord(importers[importer])[field])).flatMap(([name, spec]) => {
      const ref = asString(asRecord(spec).version) ?? asString(spec);
      const to = ref === undefined ? null : resolveRef(name, ref, importer);
      return to === null ? [] : [to];
    });

  const edges = (node: string): Edge<string>[] => {
    if (node.startsWith(IMPORTER_PREFIX)) {
      const importer = node.slice(IMPORTER_PREFIX.length);
      return [
        ...importerDeps(importer, "dependencies").map((to) => ({ to, optional: false })),
        ...importerDeps(importer, "optionalDependencies").map((to) => ({ to, optional: true })),
      ];
    }
    const snapshot = asRecord(snapshots[node]);
    const out: Edge<string>[] = [];
    for (const [field, optional] of [
      ["dependencies", false],
      ["optionalDependencies", true],
    ] as const) {
      for (const [name, ref] of Object.entries(asRecord(snapshot[field]))) {
        const to = typeof ref === "string" ? resolveRef(name, ref, null) : null;
        if (to !== null) out.push({ to, optional });
      }
    }
    return out;
  };

  const packages = new Map<string, PackageNode>();
  const warnings: string[] = [];
  for (const key of Object.keys(snapshots)) {
    const split = splitPnpmKey(key);
    if (!split) {
      warnings.push(`cannot parse package key ${key}`);
      continue;
    }
    const pkgKey = key.includes("(") ? `${split.name}@${split.version}` : key;
    const info = asRecord(meta[pkgKey]);
    // Tarball and git dependencies record the real version separately.
    const version = asString(info.version) ?? split.version;
    packages.set(key, {
      ecosystem: "npm",
      name: split.name,
      version,
      hashes: integrityHashes(asRecord(info.resolution).integrity),
    });
  }

  let selected: string[];
  if (ctx.importer === null) {
    selected = Object.keys(importers);
  } else {
    const wanted = posix.normalize(ctx.importer);
    if (importers[wanted] === undefined) {
      throw new LockfileError(`${ctx.file} has no importer for ${ctx.importer}`);
    }
    selected = [wanted];
  }
  const roots: Root<string>[] = selected.flatMap((importer) => [
    ...importerDeps(importer, "dependencies").map((to) => ({ to, kind: "required" as const })),
    ...importerDeps(importer, "optionalDependencies").map((to) => ({
      to,
      kind: "optional" as const,
    })),
    ...importerDeps(importer, "devDependencies").map((to) => ({ to, kind: "dev" as const })),
  ]);

  return finalize(ctx, { packages, roots, edges, graphKnown: true, warnings });
}
