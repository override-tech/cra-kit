import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { CliError, EXIT, UsageError } from "../errors";
import { headCommit, headCommitDate } from "../git";
import { asRecord, asString } from "../guards";
import {
  displayPath,
  type GlobalOptions,
  type Io,
  loadProject,
  outputDir,
  productVersion,
} from "../project";
import { CLI_VERSION } from "../version";

const TIMEOUT_MS = 5 * 60 * 1000;

/** The hosted service; `--to` or RELEASEKEEP_URL point at another instance. */
export const DEFAULT_SERVICE = "https://releasekeep.com";
const PATH_SEGMENT = /^[A-Za-z0-9._+-]+$/;

interface UploadFile {
  path: string;
  bytes: Buffer;
}

async function outputFiles(dir: string, shown: string): Promise<UploadFile[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    throw new UsageError(`${shown} does not exist. Run \`cra all\` before \`cra publish\`.`);
  }
  const files: UploadFile[] = [];
  for (const name of names.sort()) {
    const path = join(dir, name);
    if (!(await stat(path)).isFile() || !PATH_SEGMENT.test(name)) continue;
    files.push({ path: name, bytes: await readFile(path) });
  }
  if (!files.some((f) => f.path === "sbom.cdx.json")) {
    throw new UsageError(
      `${shown}/sbom.cdx.json is missing. Run \`cra all\` before \`cra publish\`.`,
    );
  }
  return files;
}

async function artifactFiles(cwd: string, paths: string[]): Promise<UploadFile[]> {
  const files: UploadFile[] = [];
  for (const given of paths) {
    const path = resolve(cwd, given);
    const name = basename(path);
    if (!PATH_SEGMENT.test(name)) {
      throw new UsageError(
        `artifact "${given}": file names may only use letters, digits and . _ + -`,
      );
    }
    try {
      files.push({ path: `artifacts/${name}`, bytes: await readFile(path) });
    } catch {
      throw new UsageError(`artifact "${given}" cannot be read`);
    }
  }
  const seen = new Set<string>();
  for (const f of files) {
    if (seen.has(f.path)) throw new UsageError(`two artifacts are both named ${f.path}`);
    seen.add(f.path);
  }
  return files;
}

function problemText(body: unknown, status: number): string {
  const problem = asRecord(body);
  const detail = asString(problem?.detail) ?? asString(problem?.title);
  return detail ? `${detail} (HTTP ${status})` : `HTTP ${status}`;
}

/**
 * Archive this release with the hosted ReleaseKeep service: the records `cra all`
 * wrote plus the given release artefacts, under the product version. The
 * upload token comes from RELEASEKEEP_TOKEN only, never a flag, so it stays out
 * of shell history and process lists.
 */
export async function publishCommand(
  options: GlobalOptions,
  io: Io,
  flags: { to?: string; artifact?: string[] },
): Promise<number> {
  const token = io.env.RELEASEKEEP_TOKEN?.trim();
  if (!token) {
    throw new UsageError(
      "set RELEASEKEEP_TOKEN to the product's upload token (Product > Upload tokens in ReleaseKeep)",
    );
  }
  const base = (flags.to ?? (io.env.RELEASEKEEP_URL?.trim() || DEFAULT_SERVICE))
    .trim()
    .replace(/\/+$/, "");
  if (!/^https?:\/\//.test(base)) {
    throw new UsageError(
      `--to or RELEASEKEEP_URL must be an http(s) address, e.g. ${DEFAULT_SERVICE}`,
    );
  }
  const project = await loadProject(options, io);
  const version = productVersion(project);
  const dir = outputDir(project);
  const files = [
    ...(await outputFiles(dir, displayPath(io.cwd, dir))),
    ...(await artifactFiles(project.cwd, flags.artifact ?? [])),
  ];
  const commit = io.env.GITHUB_SHA ?? headCommit(project.cwd);
  const releasedAt = headCommitDate(project.cwd);

  const form = new FormData();
  form.set("version", version);
  if (releasedAt) form.set("releasedAt", releasedAt.toISOString());
  if (commit) form.set("commit", commit);
  for (const f of files) form.append("files", new Blob([new Uint8Array(f.bytes)]), f.path);

  let response: Response;
  try {
    response = await io.fetch(`${base}/api/v1/releases`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        "user-agent": `releasekeep-cra/${CLI_VERSION}`,
      },
      body: form,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    throw new CliError(
      `could not reach ${base}: ${error instanceof Error ? error.message : String(error)}`,
      EXIT.network,
    );
  }
  const body: unknown = await response.json().catch(() => null);
  if (response.status === 409) {
    throw new CliError(
      `version ${version} is already archived with different content, and archived releases never change. Publish the change under a new version.\n${problemText(body, 409)}`,
      EXIT.usage,
    );
  }
  if (!response.ok) {
    if (response.status >= 500 || response.status === 429)
      throw new CliError(`the upload failed: ${problemText(body, response.status)}`, EXIT.network);
    throw new CliError(`the upload was refused: ${problemText(body, response.status)}`, EXIT.usage);
  }
  const result = asRecord(body);
  const pageUrl = asString(result?.pageUrl) ?? base;
  const replayed = result?.outcome === "replayed";
  if (options.json) {
    io.stdout(`${JSON.stringify(body, null, 2)}\n`);
  } else if (!options.quiet) {
    io.stdout(
      `${replayed ? "Already archived" : "Archived"} ${version}: ${files.length} files.\n` +
        `Security page: ${pageUrl}${result?.public === false ? " (private until you publish the product)" : ""}\n`,
    );
  }
  return EXIT.ok;
}
