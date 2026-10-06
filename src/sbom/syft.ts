import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, join, resolve } from "node:path";
import { promisify } from "node:util";
import type { ProductConfig } from "../config";
import { CliError } from "../errors";
import { compareStrings, isoDateTime } from "../format";
import { asArray, asRecord, asString } from "../guards";
import {
  CRA_KIT_TOOL,
  type CycloneDxBom,
  type CycloneDxComponent,
  deterministicSerial,
  productComponent,
  productRef,
} from "./cyclonedx";

const run = promisify(execFile);

/** Absolute path of `syft` on PATH, or null. */
export function findSyft(pathEnv: string | undefined): string | null {
  const names = process.platform === "win32" ? ["syft.exe", "syft"] : ["syft"];
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!dir) continue;
    for (const name of names) {
      const candidate = join(dir, name);
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // not here
      }
    }
  }
  return null;
}

async function syftScan(syft: string, dir: string): Promise<Record<string, unknown>> {
  try {
    const { stdout } = await run(syft, [`dir:${dir}`, "-o", "cyclonedx-json@1.6", "-q"], {
      maxBuffer: 512 * 1024 * 1024,
      timeout: 15 * 60 * 1000,
    });
    return asRecord(JSON.parse(stdout));
  } catch (error) {
    throw new CliError(`syft failed on ${dir}: ${String(error)}`);
  }
}

/**
 * Runs Syft on each path and rewrites the result into the same envelope as the
 * built-in generator: the product as metadata.component, cra-kit listed among
 * the tools, components and dependencies merged and sorted.
 */
export async function syftBom(
  syft: string,
  cwd: string,
  paths: string[],
  product: ProductConfig,
  version: string,
  now: Date,
): Promise<CycloneDxBom> {
  const ref = productRef(product, version);
  const components = new Map<string, CycloneDxComponent>();
  const dependencies = new Map<string, Set<string>>();
  const tools = new Map<string, CycloneDxComponent>();
  for (const path of paths) {
    const bom = await syftScan(syft, resolve(cwd, path));
    const metadata = asRecord(bom.metadata);
    const rootRef = asString(asRecord(metadata.component)["bom-ref"]);
    for (const tool of asArray(asRecord(metadata.tools).components)) {
      const t = asRecord(tool);
      const name = asString(t.name);
      if (name) tools.set(name, { type: "application", name, version: asString(t.version) });
    }
    for (const raw of asArray(bom.components)) {
      const c = asRecord(raw);
      const key = asString(c["bom-ref"]) ?? asString(c.purl) ?? asString(c.name);
      // Syft's own component shape is valid CycloneDX; it is carried over as is.
      if (key && !components.has(key)) components.set(key, raw as CycloneDxComponent);
    }
    for (const raw of asArray(bom.dependencies)) {
      const d = asRecord(raw);
      const from = asString(d.ref) === rootRef ? ref : asString(d.ref);
      if (!from) continue;
      const set = dependencies.get(from) ?? new Set<string>();
      for (const to of asArray(d.dependsOn)) if (typeof to === "string") set.add(to);
      dependencies.set(from, set);
    }
  }
  const sortedComponents = [...components.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, c]) => c);
  const body = {
    metadata: {
      timestamp: isoDateTime(now),
      lifecycles: [{ phase: "pre-build" }],
      tools: {
        components: [
          CRA_KIT_TOOL,
          ...[...tools.values()].sort((a, b) => compareStrings(a.name, b.name)),
        ],
      },
      component: productComponent(product, version),
    },
    components: sortedComponents,
    dependencies: [...dependencies.entries()]
      .sort(([a], [b]) => (a === ref ? -1 : b === ref ? 1 : compareStrings(a, b)))
      .map(([from, to]) => ({ ref: from, dependsOn: [...to].sort(compareStrings) })),
  };
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: deterministicSerial(JSON.stringify(body)),
    version: 1,
    ...body,
  };
}
