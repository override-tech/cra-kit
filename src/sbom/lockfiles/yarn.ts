import { posix } from "node:path";
import { parse } from "yaml";
import { asArray, asRecord, asString, asStringMap, isRecord } from "../../guards";
import { type Edge, integrityHashes, type Root } from "../graph";
import type { Hash, LockfileResult } from "../model";
import {
  expandWorkspaces,
  finalize,
  type LockContext,
  LockfileError,
  type PackageNode,
  parseJson,
  readSibling,
} from "./shared";

interface YarnEntry {
  /** Real package name (aliases resolved). */
  name: string;
  version: string;
  dependencies: Record<string, string>;
  optional: Set<string>;
  hashes: Hash[];
  /** Berry workspace path, when the entry is a workspace rather than a package. */
  workspace: string | null;
  /** link:, portal: and file: entries live inside the product. */
  local: boolean;
}

/** "name@range" -> [name, range]; the name may be scoped. */
function splitDescriptor(descriptor: string): [string, string] {
  const at = descriptor.indexOf("@", 1);
  return at < 0 ? [descriptor, ""] : [descriptor.slice(0, at), descriptor.slice(at + 1)];
}

const unquote = (s: string) => (s.length >= 2 && s.startsWith('"') ? s.slice(1, -1) : s);

/** Splits `"key" value` or `key value` (yarn v1 syntax). */
function splitKeyValue(line: string): [string, string] {
  if (line.startsWith('"')) {
    const end = line.indexOf('"', 1);
    return [line.slice(1, end), unquote(line.slice(end + 1).trim())];
  }
  const space = line.indexOf(" ");
  return space < 0 ? [line, ""] : [line.slice(0, space), unquote(line.slice(space + 1).trim())];
}

/** Classic yarn.lock (v1): an indentation-based format of its own. */
function parseClassic(text: string): Map<string, YarnEntry> {
  const byDescriptor = new Map<string, YarnEntry>();
  let current: { descriptors: string[]; fields: Record<string, string> } | null = null;
  let section: Record<string, string> | null = null;
  let deps: Record<string, string> = {};
  let optionalDeps: Record<string, string> = {};

  const flush = () => {
    if (!current) return;
    const first = current.descriptors[0] ?? "";
    let [name, range] = splitDescriptor(first);
    if (range.startsWith("npm:")) [name] = splitDescriptor(range.slice(4));
    const resolved = current.fields.resolved ?? "";
    const sha1 = /#([0-9a-f]{40})$/.exec(resolved)?.[1];
    const hashes = integrityHashes(current.fields.integrity);
    if (sha1 && !hashes.some((h) => h.alg === "SHA-1"))
      hashes.push({ alg: "SHA-1", content: sha1 });
    const entry: YarnEntry = {
      name,
      version: current.fields.version ?? "",
      dependencies: { ...deps, ...optionalDeps },
      optional: new Set(Object.keys(optionalDeps)),
      hashes,
      workspace: null,
      local: resolved.startsWith("file:") || range.startsWith("file:") || range.startsWith("link:"),
    };
    for (const d of current.descriptors) byDescriptor.set(d, entry);
  };

  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === "" || raw.trimStart().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      flush();
      const header = line.endsWith(":") ? line.slice(0, -1) : line;
      current = { descriptors: header.split(/,\s*/).map(unquote), fields: {} };
      deps = {};
      optionalDeps = {};
      section = null;
    } else if (current && indent <= 2) {
      if (line.endsWith(":")) {
        const key = unquote(line.slice(0, -1));
        section =
          key === "dependencies" ? deps : key === "optionalDependencies" ? optionalDeps : {};
      } else {
        const [key, value] = splitKeyValue(line);
        current.fields[key] = value;
        section = null;
      }
    } else if (current && section) {
      const [key, value] = splitKeyValue(line);
      section[key] = value;
    }
  }
  flush();
  return byDescriptor;
}

/** Name in a berry resolution ("lodash@npm:4.17.21", "x@patch:x@npm%3A1.0.0#..."). */
function berryResolution(resolution: string): { name: string; protocol: string; rest: string } {
  const [name, rest] = splitDescriptor(resolution);
  const colon = rest.indexOf(":");
  return { name, protocol: colon < 0 ? "" : rest.slice(0, colon), rest: rest.slice(colon + 1) };
}

/** Yarn 2+ (berry) lockfiles are YAML with a __metadata block. */
function parseBerry(text: string, file: string): Map<string, YarnEntry> {
  let doc: Record<string, unknown>;
  try {
    doc = asRecord(parse(text));
  } catch (error) {
    throw new LockfileError(`${file} is not valid YAML: ${String(error)}`);
  }
  const byDescriptor = new Map<string, YarnEntry>();
  for (const [key, value] of Object.entries(doc)) {
    if (key === "__metadata" || !isRecord(value)) continue;
    const resolution = berryResolution(asString(value.resolution) ?? key.split(/,\s*/)[0] ?? "");
    const meta = asRecord(value.dependenciesMeta);
    const entry: YarnEntry = {
      name: resolution.name,
      version: String(value.version ?? ""),
      dependencies: asStringMap(value.dependencies),
      optional: new Set(Object.keys(meta).filter((n) => asRecord(meta[n]).optional === true)),
      hashes: [],
      workspace: resolution.protocol === "workspace" ? resolution.rest : null,
      local: ["link", "portal", "file"].includes(resolution.protocol),
    };
    for (const d of key.split(/,\s*/)) byDescriptor.set(d.trim(), entry);
  }
  return byDescriptor;
}

interface Manifest {
  name: string | undefined;
  prod: Record<string, string>;
  optional: Record<string, string>;
  dev: Record<string, string>;
  workspaces: string[];
}

function readManifest(ctx: LockContext, dir: string): Manifest | null {
  const path = posix.join(dir, "package.json");
  const text = readSibling(ctx, path);
  if (text === null) return null;
  const pkg = asRecord(parseJson(text, path));
  const workspaces = Array.isArray(pkg.workspaces)
    ? pkg.workspaces
    : asArray(asRecord(pkg.workspaces).packages);
  return {
    name: asString(pkg.name),
    prod: { ...asStringMap(pkg.dependencies), ...asStringMap(pkg.peerDependencies) },
    optional: asStringMap(pkg.optionalDependencies),
    dev: asStringMap(pkg.devDependencies),
    workspaces: workspaces.filter((w): w is string => typeof w === "string"),
  };
}

const WORKSPACE_PREFIX = "workspace:";

/**
 * yarn.lock, classic (v1) and berry (v2+). The lockfile does not say which
 * packages are development-only, so production and development roots come
 * from the package.json files of the workspaces.
 */
export function parseYarnLock(text: string, ctx: LockContext): LockfileResult {
  const berry = /^__metadata:/m.test(text);
  const byDescriptor = berry ? parseBerry(text, ctx.file) : parseClassic(text);
  const warnings: string[] = [];

  const entryKey = (e: YarnEntry) =>
    e.workspace !== null
      ? `${WORKSPACE_PREFIX}${posix.normalize(e.workspace)}`
      : `${e.name}@${e.version}`;
  const entries = new Map<string, YarnEntry>();
  for (const e of byDescriptor.values()) entries.set(entryKey(e), e);

  const lookup = (name: string, range: string): YarnEntry | undefined =>
    byDescriptor.get(`${name}@${range}`) ??
    (berry && !range.includes(":") ? byDescriptor.get(`${name}@npm:${range}`) : undefined);

  // Workspace members: berry lists them; classic needs the package.json globs.
  const manifests = new Map<string, Manifest>();
  const rootManifest = readManifest(ctx, ".");
  if (rootManifest) manifests.set(".", rootManifest);
  const memberDirs = berry
    ? [...entries.values()].flatMap((e) =>
        e.workspace !== null ? [posix.normalize(e.workspace)] : [],
      )
    : expandWorkspaces(ctx.dir, rootManifest?.workspaces ?? [], "package.json");
  for (const dir of memberDirs) {
    if (manifests.has(dir)) continue;
    const manifest = readManifest(ctx, dir);
    if (manifest) manifests.set(dir, manifest);
  }
  const workspaceByName = new Map<string, string>();
  for (const [dir, m] of manifests) if (m.name) workspaceByName.set(m.name, dir);

  /** Dependencies of a workspace member, as nodes, with the kind the manifest gives them. */
  const memberDeps = (dir: string): Root<string>[] => {
    const manifest = manifests.get(dir);
    const lockEntry = entries.get(`${WORKSPACE_PREFIX}${dir}`);
    const out: Root<string>[] = [];
    const deps = lockEntry
      ? lockEntry.dependencies
      : { ...manifest?.dev, ...manifest?.prod, ...manifest?.optional };
    for (const [name, range] of Object.entries(deps)) {
      const kind: Root<string>["kind"] =
        manifest && name in manifest.dev && !(name in manifest.prod) && !(name in manifest.optional)
          ? "dev"
          : lockEntry?.optional.has(name) || (manifest && name in manifest.optional)
            ? "optional"
            : "required";
      const target = lookup(name, range);
      if (target) out.push({ to: entryKey(target), kind });
      else if (workspaceByName.has(name)) {
        out.push({ to: `${WORKSPACE_PREFIX}${workspaceByName.get(name)}`, kind });
      } else if (kind !== "dev" || ctx.includeDev) {
        warnings.push(
          `${name}@${range} (from ${posix.join(dir, "package.json")}) is not in the lockfile`,
        );
      }
    }
    return out;
  };

  const edges = (node: string): Edge<string>[] => {
    if (node.startsWith(WORKSPACE_PREFIX)) {
      return memberDeps(node.slice(WORKSPACE_PREFIX.length))
        .filter((r) => r.kind !== "dev")
        .map((r) => ({ to: r.to, optional: r.kind === "optional" }));
    }
    const e = entries.get(node);
    if (!e) return [];
    return Object.entries(e.dependencies).flatMap(([name, range]) => {
      const target = lookup(name, range);
      return target ? [{ to: entryKey(target), optional: e.optional.has(name) }] : [];
    });
  };

  const packages = new Map<string, PackageNode>();
  for (const [key, e] of entries) {
    if (e.workspace !== null || e.local) continue;
    packages.set(key, {
      ecosystem: "npm",
      name: e.name,
      version: e.version || null,
      hashes: e.hashes,
    });
  }

  let roots: Root<string>[];
  if (manifests.size === 0) {
    warnings.push(
      "no package.json next to the lockfile; every locked package is treated as a production dependency",
    );
    roots = [...packages.keys()].map((to) => ({ to, kind: "required" }));
  } else if (ctx.importer !== null) {
    const dir = posix.normalize(ctx.importer);
    if (!manifests.has(dir))
      throw new LockfileError(`${ctx.file} has no workspace at ${ctx.importer}`);
    roots = memberDeps(dir);
  } else {
    roots = [...manifests.keys()].flatMap(memberDeps);
  }

  return finalize(ctx, { packages, roots, edges, graphKnown: true, warnings });
}
