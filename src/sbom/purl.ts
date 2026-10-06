import type { Ecosystem } from "./model";

/**
 * Package URLs (https://github.com/package-url/purl-spec). Names are split
 * into namespace segments on "/" (npm scope, Go module path, Composer vendor)
 * and each segment is percent-encoded the way packageurl-js does.
 */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment)
    .replace(/%3A/gi, ":")
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** PEP 503 normalised Python project name, as the purl spec requires for pypi. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export function makePurl(type: Ecosystem, name: string, version: string | null): string {
  const normalized =
    type === "pypi" ? normalizePypiName(name) : type === "composer" ? name.toLowerCase() : name;
  const path = normalized.split("/").map(encodeSegment).join("/");
  return `pkg:${type}/${path}${version ? `@${encodeSegment(version)}` : ""}`;
}

export interface ParsedPurl {
  type: string;
  /** Namespace and name joined with "/", decoded. */
  name: string;
  version: string | null;
}

export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith("pkg:")) return null;
  let rest = purl.slice(4);
  for (const separator of ["#", "?"]) {
    const index = rest.indexOf(separator);
    if (index >= 0) rest = rest.slice(0, index);
  }
  const slash = rest.indexOf("/");
  if (slash <= 0) return null;
  const type = rest.slice(0, slash).toLowerCase();
  let path = rest.slice(slash + 1);
  let version: string | null = null;
  const at = path.lastIndexOf("@");
  if (at > 0) {
    version = decodeURIComponent(path.slice(at + 1));
    path = path.slice(0, at);
  }
  const name = path
    .split("/")
    .filter((s) => s !== "")
    .map((s) => decodeURIComponent(s))
    .join("/");
  return name ? { type, name, version } : null;
}

/** purl type to OSV ecosystem name (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export const OSV_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  golang: "Go",
  cargo: "crates.io",
  composer: "Packagist",
  maven: "Maven",
  nuget: "NuGet",
  gem: "RubyGems",
  hex: "Hex",
  pub: "Pub",
  swift: "SwiftURL",
};
