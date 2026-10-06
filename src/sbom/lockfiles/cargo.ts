import { posix } from "node:path";
import { parse as parseToml } from "smol-toml";
import { asArray, asRecord, asString, isRecord } from "../../guards";
import type { Edge, Root } from "../graph";
import type { LockfileResult } from "../model";
import {
  expandWorkspaces,
  finalize,
  type LockContext,
  LockfileError,
  type PackageNode,
  readSibling,
} from "./shared";

function toml(text: string, file: string): Record<string, unknown> {
  try {
    return parseToml(text);
  } catch (error) {
    throw new LockfileError(`${file} is not valid TOML: ${String(error)}`);
  }
}

interface MemberManifest {
  prod: Set<string>;
  dev: Set<string>;
}

/** Crate names a manifest depends on, per table kind; `package = "..."` renames are resolved. */
function memberManifest(manifest: Record<string, unknown>): MemberManifest {
  const prod = new Set<string>();
  const dev = new Set<string>();
  const collect = (table: unknown, into: Set<string>) => {
    for (const [key, spec] of Object.entries(asRecord(table))) {
      into.add((isRecord(spec) ? asString(spec.package) : undefined) ?? key);
    }
  };
  const tables = [manifest, ...Object.values(asRecord(manifest.target)).map(asRecord)];
  for (const t of tables) {
    collect(t.dependencies, prod);
    collect(t["build-dependencies"], prod);
    collect(t["dev-dependencies"], dev);
  }
  return { prod, dev };
}

/** Workspace members by crate name, from Cargo.toml next to the lockfile. */
function readMembers(ctx: LockContext): Map<string, MemberManifest> {
  const members = new Map<string, MemberManifest>();
  const rootText = readSibling(ctx, "Cargo.toml");
  if (rootText === null) return members;
  const root = toml(rootText, "Cargo.toml");
  const workspace = asRecord(root.workspace);
  const excluded = new Set(
    asArray(workspace.exclude).filter((e): e is string => typeof e === "string"),
  );
  const dirs = [
    ...(root.package !== undefined ? ["."] : []),
    ...expandWorkspaces(
      ctx.dir,
      asArray(workspace.members).filter((m): m is string => typeof m === "string"),
      "Cargo.toml",
    ).filter((d) => !excluded.has(d)),
  ];
  for (const dir of dirs) {
    const path = posix.join(dir, "Cargo.toml");
    const text = dir === "." ? rootText : readSibling(ctx, path);
    if (text === null) continue;
    const manifest = toml(text, path);
    const name = asString(asRecord(manifest.package).name);
    if (name) members.set(name, memberManifest(manifest));
  }
  return members;
}

/**
 * Cargo.lock (versions 1-4). Workspace members are the packages without a
 * `source`; whether a dependency is development-only comes from their
 * Cargo.toml, since the lockfile does not record it.
 */
export function parseCargoLock(text: string, ctx: LockContext): LockfileResult {
  const lock = toml(text, ctx.file);
  const list = asArray(lock.package).map(asRecord);
  const warnings: string[] = [];
  const byName = new Map<string, string[]>();
  const info = new Map<string, Record<string, unknown>>();
  for (const p of list) {
    const name = asString(p.name);
    const version = asString(p.version);
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    info.set(key, p);
    byName.set(name, [...(byName.get(name) ?? []), key]);
  }

  /** "name", "name version" or "name version (source)" to a node key. */
  const resolve = (dep: string): string | null => {
    const [name = "", version] = dep.split(" ");
    if (version !== undefined) return info.has(`${name}@${version}`) ? `${name}@${version}` : null;
    const candidates = byName.get(name) ?? [];
    return candidates.length === 1 ? (candidates[0] ?? null) : null;
  };

  const members = readMembers(ctx);
  const isMember = (key: string) => asString(info.get(key)?.source) === undefined;
  /** Dependencies of a node; for members, with dev-only ones marked as such. */
  const depsOf = (key: string): Root<string>[] => {
    const p = info.get(key);
    const manifest = isMember(key) ? members.get(asString(p?.name) ?? "") : undefined;
    return asArray(p?.dependencies).flatMap((d) => {
      const to = typeof d === "string" ? resolve(d) : null;
      if (to === null) return [];
      const name = to.slice(0, to.lastIndexOf("@"));
      const devOnly = manifest?.dev.has(name) && !manifest.prod.has(name);
      return [{ to, kind: devOnly ? ("dev" as const) : ("required" as const) }];
    });
  };

  const packages = new Map<string, PackageNode>();
  for (const [key, p] of info) {
    if (isMember(key)) continue;
    const checksum = asString(p.checksum);
    packages.set(key, {
      ecosystem: "cargo",
      name: asString(p.name) ?? "",
      version: asString(p.version) ?? null,
      hashes:
        checksum && /^[0-9a-f]{64}$/.test(checksum) ? [{ alg: "SHA-256", content: checksum }] : [],
    });
  }

  const memberKeys = [...info.keys()].filter(isMember);
  if (memberKeys.length > 0 && members.size === 0) {
    warnings.push("Cargo.toml not found or unreadable; dev-dependencies cannot be told apart");
  }
  const roots: Root<string>[] =
    memberKeys.length > 0
      ? memberKeys.flatMap(depsOf)
      : [...packages.keys()].map((to) => ({ to, kind: "required" }));
  const edges = (key: string): Edge<string>[] =>
    depsOf(key)
      .filter((d) => d.kind !== "dev")
      .map((d) => ({ to: d.to, optional: false }));

  return finalize(ctx, { packages, roots, edges, graphKnown: true, warnings });
}
