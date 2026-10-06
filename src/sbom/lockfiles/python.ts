import { posix } from "node:path";
import { parse as parseToml } from "smol-toml";
import { asArray, asRecord, asString, isRecord } from "../../guards";
import type { Edge, Root } from "../graph";
import type { LockfileResult } from "../model";
import { normalizePypiName } from "../purl";
import { finalize, type LockContext, LockfileError, type PackageNode, readSibling } from "./shared";

const PEP508_NAME = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/;

/** Name and pinned version of a PEP 508 requirement; version is null unless pinned with == or ===. */
export function parseRequirement(spec: string): { name: string; version: string | null } | null {
  const match = PEP508_NAME.exec(spec);
  if (!match?.[1]) return null;
  let rest = spec.slice(match[0].length).trim();
  if (rest.startsWith("[")) rest = rest.slice(rest.indexOf("]") + 1).trim();
  rest = rest.split(";")[0]?.trim() ?? "";
  const pinned = /^===?\s*([^\s,*]+)$/.exec(rest);
  return { name: match[1], version: pinned?.[1] ?? null };
}

/** requirements.txt, following -r includes. Only == pins give versions. */
export function parseRequirements(text: string, ctx: LockContext): LockfileResult {
  const packages = new Map<string, PackageNode>();
  const warnings: string[] = [];
  const visited = new Set<string>();

  const readFile = (content: string, file: string) => {
    visited.add(file);
    const logical = content.replace(/\\\r?\n/g, " ").split(/\r?\n/);
    for (const raw of logical) {
      const line = raw.replace(/(^|\s)#.*$/, "").trim();
      if (!line) continue;
      const include = /^(?:-r|--requirement)(?:\s+|=)(\S+)/.exec(line);
      if (include?.[1]) {
        const target = posix.normalize(posix.join(posix.dirname(file), include[1]));
        if (visited.has(target)) continue;
        const included = readSibling(ctx, target);
        if (included === null) warnings.push(`included file ${target} not found`);
        else readFile(included, target);
        continue;
      }
      if (/^(?:-e|--editable)\b/.test(line)) {
        warnings.push(`editable requirement skipped: ${line}`);
        continue;
      }
      if (line.startsWith("-")) continue; // --index-url, -c constraints, --hash on its own line
      const spec = line.replace(/\s--hash[=\s]\S+/g, "").trim();
      const req = parseRequirement(spec);
      if (!req || /^(?:https?|git\+|file):|^[./]/.test(spec)) {
        warnings.push(`unsupported requirement skipped: ${spec}`);
        continue;
      }
      if (req.version === null) {
        warnings.push(
          `${req.name} is not pinned with ==; pin it (pip freeze, pip-compile) so it can be scanned`,
        );
      }
      const key = normalizePypiName(req.name);
      if (!packages.has(key))
        packages.set(key, { ecosystem: "pypi", name: req.name, version: req.version });
    }
  };
  readFile(text, posix.basename(ctx.file));

  const roots: Root<string>[] = [...packages.keys()].map((to) => ({ to, kind: "required" }));
  return finalize(ctx, { packages, roots, edges: () => [], graphKnown: false, warnings });
}

function tomlOrThrow(text: string, file: string): Record<string, unknown> {
  try {
    return parseToml(text);
  } catch (error) {
    throw new LockfileError(`${file} is not valid TOML: ${String(error)}`);
  }
}

/** Roots declared in pyproject.toml (Poetry tables and PEP 621). */
function pyprojectRoots(
  pyproject: Record<string, unknown>,
): Array<{ name: string; kind: Root<string>["kind"] }> {
  const out: Array<{ name: string; kind: Root<string>["kind"] }> = [];
  const poetry = asRecord(asRecord(pyproject.tool).poetry);
  const fromTable = (table: unknown, kind: Root<string>["kind"]) => {
    for (const [name, spec] of Object.entries(asRecord(table))) {
      if (name.toLowerCase() === "python") continue;
      const optional = isRecord(spec) && spec.optional === true;
      out.push({ name, kind: kind === "required" && optional ? "optional" : kind });
    }
  };
  fromTable(poetry.dependencies, "required");
  fromTable(poetry["dev-dependencies"], "dev");
  for (const [group, body] of Object.entries(asRecord(poetry.group))) {
    fromTable(asRecord(body).dependencies, group === "main" ? "required" : "dev");
  }
  const project = asRecord(pyproject.project);
  const fromList = (list: unknown, kind: Root<string>["kind"]) => {
    for (const spec of asArray(list)) {
      const req = typeof spec === "string" ? parseRequirement(spec) : null;
      if (req) out.push({ name: req.name, kind });
    }
  };
  fromList(project.dependencies, "required");
  for (const list of Object.values(asRecord(project["optional-dependencies"])))
    fromList(list, "optional");
  for (const list of Object.values(asRecord(pyproject["dependency-groups"]))) fromList(list, "dev");
  return out;
}

/**
 * poetry.lock. Production vs development comes from `groups` (lock 2.1),
 * `category` (older lockfiles) or, failing both, from pyproject.toml roots.
 */
export function parsePoetryLock(text: string, ctx: LockContext): LockfileResult {
  const lock = tomlOrThrow(text, ctx.file);
  const warnings: string[] = [];
  const packages = new Map<string, PackageNode>();
  const byName = new Map<string, string[]>();
  const declared = new Map<string, Root<string>["kind"]>();
  const deps = new Map<string, Array<{ name: string; optional: boolean }>>();

  for (const raw of asArray(lock.package)) {
    const p = asRecord(raw);
    const name = asString(p.name);
    if (!name) continue;
    const version = asString(p.version) ?? null;
    const key = `${normalizePypiName(name)}@${version ?? ""}`;
    packages.set(key, { ecosystem: "pypi", name, version });
    byName.set(normalizePypiName(name), [...(byName.get(normalizePypiName(name)) ?? []), key]);
    const groups = asArray(p.groups).filter((g): g is string => typeof g === "string");
    const category = asString(p.category);
    if (groups.length > 0 || category) {
      const main = groups.length > 0 ? groups.includes("main") : category === "main";
      declared.set(key, !main ? "dev" : p.optional === true ? "optional" : "required");
    }
    deps.set(
      key,
      Object.entries(asRecord(p.dependencies)).map(([depName, spec]) => ({
        name: normalizePypiName(depName),
        optional: isRecord(spec)
          ? spec.optional === true
          : Array.isArray(spec) &&
            spec.length > 0 &&
            spec.every((s) => asRecord(s).optional === true),
      })),
    );
  }

  const edges = (key: string): Edge<string>[] =>
    (deps.get(key) ?? []).flatMap((d) =>
      (byName.get(d.name) ?? []).map((to) => ({ to, optional: d.optional })),
    );

  const pyprojectText = readSibling(ctx, "pyproject.toml");
  const declaredRoots = pyprojectText
    ? pyprojectRoots(tomlOrThrow(pyprojectText, "pyproject.toml"))
    : [];
  let roots: Root<string>[];
  if (declared.size > 0) {
    // The lockfile itself says which packages are production ones.
    roots = [...declared].map(([to, kind]) => ({ to, kind }));
  } else if (declaredRoots.length > 0) {
    roots = declaredRoots.flatMap((r) =>
      (byName.get(normalizePypiName(r.name)) ?? []).map((to) => ({ to, kind: r.kind })),
    );
  } else {
    warnings.push(
      "no dependency groups in the lockfile and no pyproject.toml; every locked package is treated as a production dependency",
    );
    roots = [...packages.keys()].map((to) => ({ to, kind: "required" }));
  }
  // When the lockfile classifies every package itself, pyproject.toml still says which are direct.
  const direct =
    declared.size > 0 && declaredRoots.length > 0
      ? declaredRoots
          .filter((r) => r.kind !== "dev" || ctx.includeDev)
          .flatMap((r) => byName.get(normalizePypiName(r.name)) ?? [])
      : undefined;
  return finalize(ctx, { packages, roots, edges, graphKnown: true, warnings, direct });
}
