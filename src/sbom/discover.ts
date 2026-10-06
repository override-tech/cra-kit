import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { UsageError } from "../errors";
import { parseCargoLock } from "./lockfiles/cargo";
import { parseComposerLock } from "./lockfiles/composer";
import { parseGoMod } from "./lockfiles/go";
import { parseNpmLock } from "./lockfiles/npm";
import { parsePnpmLock } from "./lockfiles/pnpm";
import { parsePoetryLock, parseRequirements } from "./lockfiles/python";
import type { LockContext } from "./lockfiles/shared";
import { parseYarnLock } from "./lockfiles/yarn";
import { type Inventory, type LockfileResult, mergeResults } from "./model";

type Parser = (text: string, ctx: LockContext) => LockfileResult;

/** Supported lockfiles, in the order they are read within one directory. */
export const LOCKFILES: ReadonlyArray<{ file: string; parse: Parser }> = [
  { file: "package-lock.json", parse: parseNpmLock },
  { file: "npm-shrinkwrap.json", parse: parseNpmLock },
  { file: "pnpm-lock.yaml", parse: parsePnpmLock },
  { file: "yarn.lock", parse: parseYarnLock },
  { file: "poetry.lock", parse: parsePoetryLock },
  { file: "requirements.txt", parse: parseRequirements },
  { file: "go.mod", parse: parseGoMod },
  { file: "Cargo.lock", parse: parseCargoLock },
  { file: "composer.lock", parse: parseComposerLock },
];

/** JavaScript lockfiles that may sit at a workspace root above the configured path. */
const WORKSPACE_LOCKFILES = new Set(["pnpm-lock.yaml", "package-lock.json", "yarn.lock"]);

function parserFor(fileName: string): Parser | undefined {
  if (/^requirements.*\.txt$/.test(fileName)) return parseRequirements;
  return LOCKFILES.find((l) => l.file === fileName)?.parse;
}

const toPosix = (path: string) => path.split(sep).join("/");

interface Job {
  lockfile: string;
  importer: string | null;
  parse: Parser;
}

function jobsFor(cwd: string, configured: string): Job[] {
  const target = resolve(cwd, configured);
  if (!existsSync(target)) throw new UsageError(`sbom.paths: ${configured} does not exist`);
  if (statSync(target).isFile()) {
    const parse = parserFor(basename(target));
    if (!parse) {
      throw new UsageError(
        `sbom.paths: ${configured} is not a supported lockfile (${LOCKFILES.map((l) => l.file).join(", ")})`,
      );
    }
    return [{ lockfile: target, importer: null, parse }];
  }
  const local = LOCKFILES.filter((l) => existsSync(join(target, l.file)));
  if (local.length > 0) {
    return local.map((l) => ({ lockfile: join(target, l.file), importer: null, parse: l.parse }));
  }
  // A package inside a JavaScript monorepo: use the workspace lockfile, scoped to it.
  if (existsSync(join(target, "package.json"))) {
    for (let dir = dirname(target); ; dir = dirname(dir)) {
      const found = LOCKFILES.filter(
        (l) => WORKSPACE_LOCKFILES.has(l.file) && existsSync(join(dir, l.file)),
      );
      if (found.length > 0) {
        return found.map((l) => ({
          lockfile: join(dir, l.file),
          importer: toPosix(relative(dir, target)),
          parse: l.parse,
        }));
      }
      if (existsSync(join(dir, ".git")) || dirname(dir) === dir) break;
    }
  }
  throw new UsageError(
    `sbom.paths: no lockfile found in ${configured}. Supported: ${LOCKFILES.map((l) => l.file).join(", ")}`,
  );
}

/** Reads every lockfile under the configured paths into one de-duplicated inventory. */
export function buildInventory(cwd: string, paths: string[], includeDev: boolean): Inventory {
  const seen = new Set<string>();
  const results: LockfileResult[] = [];
  for (const configured of paths) {
    for (const job of jobsFor(cwd, configured)) {
      const id = `${job.lockfile}\0${job.importer ?? ""}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const file = toPosix(relative(cwd, job.lockfile)) || basename(job.lockfile);
      const ctx: LockContext = {
        file: job.importer ? `${file}#${job.importer}` : file,
        dir: dirname(job.lockfile),
        includeDev,
        importer: job.importer,
      };
      results.push(job.parse(readFileSync(job.lockfile, "utf8"), ctx));
    }
  }
  return mergeResults(results);
}
