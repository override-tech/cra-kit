import { asArray, asRecord, asString, asStringMap } from "../../guards";
import { type Edge, licenseStrings, type Root } from "../graph";
import type { LockfileResult } from "../model";
import { finalize, type LockContext, type PackageNode, parseJson, readSibling } from "./shared";

/**
 * composer.lock. Composer already splits production (`packages`) from
 * development (`packages-dev`) dependencies; composer.json names the direct ones.
 */
export function parseComposerLock(text: string, ctx: LockContext): LockfileResult {
  const lock = asRecord(parseJson(text, ctx.file));
  const packages = new Map<string, PackageNode>();
  const requires = new Map<string, string[]>();
  const roots: Root<string>[] = [];

  for (const [section, kind] of [
    ["packages", "required"],
    ["packages-dev", "dev"],
  ] as const) {
    for (const raw of asArray(lock[section])) {
      const p = asRecord(raw);
      const name = asString(p.name)?.toLowerCase();
      if (!name || packages.has(name)) continue;
      const version = asString(p.version);
      const shasum = asString(asRecord(p.dist).shasum);
      packages.set(name, {
        ecosystem: "composer",
        name,
        // Packagist tags are often "v1.2.3"; advisories use "1.2.3".
        version: version ? version.replace(/^v(?=\d)/, "") : null,
        licenses: licenseStrings(p.license),
        hashes: shasum && /^[0-9a-f]{40}$/.test(shasum) ? [{ alg: "SHA-1", content: shasum }] : [],
      });
      requires.set(
        name,
        Object.keys(asStringMap(p.require)).map((n) => n.toLowerCase()),
      );
      roots.push({ to: name, kind });
    }
  }

  // Platform requirements (php, ext-*) have no package and drop out here.
  const edges = (name: string): Edge<string>[] =>
    (requires.get(name) ?? [])
      .filter((n) => packages.has(n))
      .map((to) => ({ to, optional: false }));

  const manifestText = readSibling(ctx, "composer.json");
  let direct: string[];
  if (manifestText !== null) {
    const manifest = asRecord(parseJson(manifestText, "composer.json"));
    direct = [
      ...Object.keys(asStringMap(manifest.require)),
      ...(ctx.includeDev ? Object.keys(asStringMap(manifest["require-dev"])) : []),
    ]
      .map((n) => n.toLowerCase())
      .filter((n) => packages.has(n));
  } else {
    const required = new Set([...requires.values()].flat());
    direct = roots.filter((r) => r.kind === "required" && !required.has(r.to)).map((r) => r.to);
  }

  return finalize(ctx, { packages, roots, edges, graphKnown: true, direct });
}
