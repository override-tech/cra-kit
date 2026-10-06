import type { Root } from "../graph";
import type { LockfileResult } from "../model";
import { finalize, type LockContext, type PackageNode, readSibling } from "./shared";

interface Requirement {
  path: string;
  version: string;
  indirect: boolean;
}

interface Replacement {
  oldPath: string;
  oldVersion: string | null;
  newPath: string;
  newVersion: string | null;
}

const unquote = (s: string) => s.replace(/^"(.*)"$/, "$1").replace(/^`(.*)`$/, "$1");

/** Compares Go module versions (vMAJOR.MINOR.PATCH[-pre]); good enough to pick the newest. */
export function compareGoVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core = "", pre = ""] = v
      .replace(/^v/, "")
      .replace(/\+incompatible$/, "")
      .split(/-(.*)/s);
    return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const diff = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

export function parseGoModText(text: string): {
  goVersion: string | null;
  requires: Requirement[];
  replaces: Replacement[];
} {
  const requires: Requirement[] = [];
  const replaces: Replacement[] = [];
  let goVersion: string | null = null;
  let block: string | null = null;

  for (const raw of text.split(/\r?\n/)) {
    const commentAt = raw.indexOf("//");
    const comment = commentAt >= 0 ? raw.slice(commentAt + 2).trim() : "";
    const line = (commentAt >= 0 ? raw.slice(0, commentAt) : raw).trim();
    if (!line) continue;
    if (block !== null && line === ")") {
      block = null;
      continue;
    }
    let verb: string;
    let args: string[];
    if (block !== null) {
      verb = block;
      args = line.split(/\s+/);
    } else {
      const [first = "", ...rest] = line.split(/\s+/);
      if (rest[0] === "(" && rest.length === 1) {
        block = first;
        continue;
      }
      verb = first;
      args = rest;
    }
    args = args.map(unquote);
    if (verb === "go" && args[0]) goVersion = args[0];
    if (verb === "require" && args.length >= 2 && args[0] && args[1]) {
      requires.push({
        path: args[0],
        version: args[1],
        indirect: /(^|;)\s*indirect\b/.test(comment),
      });
    }
    if (verb === "replace") {
      const arrow = args.indexOf("=>");
      if (arrow < 1) continue;
      const left = args.slice(0, arrow);
      const right = args.slice(arrow + 1);
      if (!left[0] || !right[0]) continue;
      replaces.push({
        oldPath: left[0],
        oldVersion: left[1] ?? null,
        newPath: right[0],
        newVersion: right[1] ?? null,
      });
    }
  }
  return { goVersion, requires, replaces };
}

/**
 * go.mod (with go.sum as a fallback for modules older than Go 1.17, whose
 * go.mod does not list the full build list). No dependency graph.
 */
export function parseGoMod(text: string, ctx: LockContext): LockfileResult {
  const { goVersion, requires, replaces } = parseGoModText(text);
  const warnings: string[] = [];
  const packages = new Map<string, PackageNode>();
  const roots: Root<string>[] = [];

  /** Adds a module (after replace directives); returns its node key, or null when local. */
  const add = (path: string, version: string): string | null => {
    const replacement =
      replaces.find((r) => r.oldPath === path && r.oldVersion === version) ??
      replaces.find((r) => r.oldPath === path && r.oldVersion === null);
    let modulePath = path;
    let moduleVersion = version;
    if (replacement) {
      if (/^(\.{1,2}\/|\/)/.test(replacement.newPath)) {
        warnings.push(
          `${path} is replaced by the local directory ${replacement.newPath}; not listed`,
        );
        return null;
      }
      modulePath = replacement.newPath;
      moduleVersion = replacement.newVersion ?? version;
    }
    const key = `${modulePath}@${moduleVersion}`;
    if (!packages.has(key)) {
      packages.set(key, { ecosystem: "golang", name: modulePath, version: moduleVersion });
      roots.push({ to: key, kind: "required" });
    }
    return key;
  };

  const direct: string[] = [];
  for (const r of requires) {
    const key = add(r.path, r.version);
    if (key !== null && !r.indirect) direct.push(key);
  }

  const [major = 0, minor = 0] = (goVersion ?? "0.0").split(".").map(Number);
  const pruned = major > 1 || (major === 1 && minor >= 17);
  if (!pruned) {
    const sum = readSibling(ctx, "go.sum");
    if (sum === null) {
      warnings.push(
        "go.mod predates Go 1.17 and there is no go.sum; indirect modules may be missing",
      );
    } else {
      // Modules whose source was downloaded (a zip hash line) took part in the build.
      const listed = new Set(requires.map((r) => r.path));
      const newest = new Map<string, string>();
      for (const line of sum.split(/\r?\n/)) {
        const [path, version] = line.trim().split(/\s+/);
        if (!path || !version || version.endsWith("/go.mod") || listed.has(path)) continue;
        const seen = newest.get(path);
        if (!seen || compareGoVersions(version, seen) > 0) newest.set(path, version);
      }
      for (const [path, version] of newest) add(path, version);
    }
  }

  return finalize(ctx, { packages, roots, edges: () => [], graphKnown: false, warnings, direct });
}
