import { createHash } from "node:crypto";
import { relative, resolve } from "node:path";
import { type CraConfig, type FailOn, loadConfig, type ProductConfig } from "./config";
import { UsageError } from "./errors";
import { startOfDay } from "./format";
import { headCommitDate, tagVersion } from "./git";
import { assessCraScope, type CraScopeAnswers, type CraScopeResult } from "./rules";
import { bomPackages, buildBom, type CycloneDxBom, serializeBom } from "./sbom/cyclonedx";
import { buildInventory } from "./sbom/discover";
import { findSyft, syftBom } from "./sbom/syft";
import type { FetchLike } from "./scan/net";
import { runScan, type ScanReport } from "./scan/scan";

/** Everything the CLI touches outside its own code, so tests can substitute it. */
export interface Io {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  fetch: FetchLike;
  /** Working directory the CLI was started in. */
  cwd: string;
  /** Delay between network retries (tests pass 0). */
  retryDelayMs?: number;
}

export interface GlobalOptions {
  config?: string;
  cwd?: string;
  offline: boolean;
  json: boolean;
  quiet: boolean;
  now?: Date;
  productVersion?: string;
  failOn?: FailOn;
}

export interface Project {
  cwd: string;
  configPath: string;
  config: CraConfig;
  placeholders: string[];
  now: Date;
  /** Day the release is dated: --now, SOURCE_DATE_EPOCH, the HEAD commit, or today. */
  releaseDate: Date;
  offline: boolean;
  failOn: FailOn;
  io: Io;
  options: GlobalOptions;
}

export function resolveNow(options: GlobalOptions, env: Io["env"]): { now: Date; pinned: boolean } {
  if (options.now) return { now: options.now, pinned: true };
  const epoch = env.SOURCE_DATE_EPOCH;
  if (epoch && /^\d+$/.test(epoch)) return { now: new Date(Number(epoch) * 1000), pinned: true };
  return { now: new Date(), pinned: false };
}

/** A path relative to where cra was started, or absolute when it lies outside. */
export function displayPath(from: string, path: string): string {
  const rel = relative(from, path);
  return rel === "" || rel.startsWith("..") ? path : rel;
}

export async function loadProject(options: GlobalOptions, io: Io): Promise<Project> {
  const cwd = resolve(io.cwd, options.cwd ?? ".");
  const configPath = resolve(cwd, options.config ?? "cra.yml");
  const display = displayPath(io.cwd, configPath);
  const { config, placeholders } = await loadConfig(configPath, display);
  const { now, pinned } = resolveNow(options, io.env);
  const releaseDate = startOfDay(pinned ? now : (headCommitDate(cwd) ?? now));
  if (placeholders.length > 0 && !options.quiet) {
    io.stderr(
      `warning: ${display} still has TODO placeholders: ${placeholders.join(", ")}\n` +
        "         the generated documents will repeat them until you fill them in.\n",
    );
  }
  return {
    cwd,
    configPath,
    config,
    placeholders,
    now,
    releaseDate,
    offline: options.offline,
    failOn: options.failOn ?? config.scan.failOn,
    io,
    options,
  };
}

/** --version flag, then product.version, then the git tag. */
export function productVersion(project: Project): string {
  const version =
    project.options.productVersion ??
    project.config.product.version ??
    tagVersion(project.cwd, project.io.env);
  if (!version) {
    throw new UsageError(
      "The product version is unknown. Set product.version in cra.yml, pass --version <version>, or run on a git tag (v1.2.3).",
    );
  }
  return version;
}

export function scopeAnswers(product: ProductConfig): CraScopeAnswers {
  return {
    distribution: product.distribution,
    availableInEu: product.availableInEu,
    monetisation: product.monetisation,
    isFoss: product.isFoss,
    isOpenSourceSteward: product.isOpenSourceSteward,
    coreFunction: product.coreFunction,
    publicTechnicalDocs: product.publicTechnicalDocs,
    placedOnMarketAt: product.placedOnMarketAt,
    substantialModificationAfterApplication: product.substantialModificationAfterApplication,
  };
}

export function assessScope(project: Project): CraScopeResult {
  return assessCraScope(scopeAnswers(project.config.product));
}

export interface SbomResult {
  bom: CycloneDxBom;
  text: string;
  sha256: string;
  generator: "syft" | "builtin";
  lockfiles: string[];
  directCount: number;
  warnings: string[];
}

export async function generateSbom(project: Project, version: string): Promise<SbomResult> {
  const { config, cwd, now } = project;
  const syft = config.sbom.generator === "builtin" ? null : findSyft(project.io.env.PATH);
  if (config.sbom.generator === "syft" && !syft) {
    throw new UsageError(
      "sbom.generator is syft, but syft is not on PATH (https://github.com/anchore/syft)",
    );
  }
  let bom: CycloneDxBom;
  let lockfiles: string[] = [];
  let warnings: string[] = [];
  if (syft) {
    bom = await syftBom(syft, cwd, config.sbom.paths, config.product, version, now);
  } else {
    const inventory = buildInventory(cwd, config.sbom.paths, config.sbom.includeDev);
    bom = buildBom(inventory, config.product, version, now);
    lockfiles = inventory.lockfiles;
    warnings = inventory.warnings;
  }
  const text = serializeBom(bom);
  return {
    bom,
    text,
    sha256: createHash("sha256").update(text).digest("hex"),
    generator: syft ? "syft" : "builtin",
    lockfiles,
    directCount: bom.dependencies[0]?.dependsOn.length ?? 0,
    warnings,
  };
}

export function scanBom(project: Project, bom: unknown): Promise<ScanReport> {
  return runScan(bomPackages(bom), {
    fetch: project.io.fetch,
    cacheDir: resolve(project.cwd, ".cra-cache"),
    now: project.now,
    offline: project.offline,
    osvApi: project.io.env.CRA_OSV_API,
    kevUrl: project.io.env.CRA_KEV_URL,
    retryDelayMs: project.io.retryDelayMs,
  });
}

export function outputDir(project: Project): string {
  return resolve(project.cwd, project.config.output.dir);
}
