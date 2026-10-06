import { readFile } from "node:fs/promises";
import { isMap, isNode, LineCounter, parseDocument } from "yaml";
import { ConfigError, errnoCode, UsageError } from "./errors";
import { isOneOf, isRecord } from "./guards";
import {
  type CoreFunction,
  CRITICAL,
  DISTRIBUTION_MODELS,
  type DistributionModel,
  IMPORTANT_CLASS_I,
  IMPORTANT_CLASS_II,
  MONETISATION,
  type Monetisation,
} from "./rules";

export const CORE_FUNCTIONS: readonly CoreFunction[] = [
  "none_of_the_above",
  ...IMPORTANT_CLASS_I,
  ...IMPORTANT_CLASS_II,
  ...CRITICAL,
];
export const FAIL_ON = ["kev", "critical", "high", "none"] as const;
export type FailOn = (typeof FAIL_ON)[number];
export const SBOM_GENERATORS = ["auto", "syft", "builtin"] as const;
export type SbomGenerator = (typeof SBOM_GENERATORS)[number];

export interface Manufacturer {
  name: string;
  address: string;
  email: string;
  website: string | null;
}

export interface SecurityContact {
  email: string;
  /** Page with the coordinated vulnerability disclosure policy (security.txt `Policy`). */
  url: string | null;
  /** `https://` URL of the key, or `openpgp4fpr:<fingerprint>`. */
  pgpKey: string | null;
}

export interface ProductConfig {
  name: string;
  version: string | null;
  manufacturer: Manufacturer;
  distribution: DistributionModel;
  coreFunction: CoreFunction;
  availableInEu: boolean;
  isFoss: boolean;
  isOpenSourceSteward: boolean;
  publicTechnicalDocs: boolean;
  monetisation: Monetisation[];
  placedOnMarketAt: Date | null;
  substantialModificationAfterApplication: boolean;
  intendedPurpose: string;
  /** Last day of the support period (a `YYYY-MM` value means the last day of that month). */
  supportEndsAt: Date;
  expectedUseYears: number | null;
  securityContact: SecurityContact;
  languages: string[];
}

export interface CraConfig {
  product: ProductConfig;
  sbom: { paths: string[]; includeDev: boolean; generator: SbomGenerator };
  scan: { failOn: FailOn };
  output: { dir: string };
}

export interface LoadedConfig {
  config: CraConfig;
  /** Fields still holding a TODO placeholder from `cra init`. */
  placeholders: string[];
}

type Path = Array<string | number>;
interface Problem {
  path: Path;
  message: string;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LANGUAGE = /^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*$/;
const FINGERPRINT = /^(?:[0-9a-fA-F]{4}\s*){10}$/;
const MONTH = /^(\d{4})-(\d{2})$/;
const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

const SHAPE: Record<string, readonly string[]> = {
  "": ["product", "sbom", "scan", "output"],
  product: [
    "name",
    "version",
    "manufacturer",
    "distribution",
    "coreFunction",
    "availableInEu",
    "isFoss",
    "isOpenSourceSteward",
    "publicTechnicalDocs",
    "monetisation",
    "placedOnMarketAt",
    "substantialModificationAfterApplication",
    "intendedPurpose",
    "supportEndsAt",
    "expectedUseYears",
    "securityContact",
    "languages",
  ],
  "product.manufacturer": ["name", "address", "email", "website"],
  "product.securityContact": ["email", "url", "pgpKey"],
  sbom: ["paths", "includeDev", "generator"],
  scan: ["failOn"],
  output: ["dir"],
};

function describe(value: unknown): string {
  if (value === null || value === undefined) return "nothing";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "a list";
  if (typeof value === "object") return "a mapping";
  return `${typeof value} ${String(value)}`;
}

function levenshtein(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const current = row[j] ?? 0;
      row[j] = Math.min(
        (row[j] ?? 0) + 1,
        (row[j - 1] ?? 0) + 1,
        previous + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      previous = current;
    }
  }
  return row[b.length] ?? 0;
}

function suggest(input: string, options: readonly string[]): string {
  const lower = input.toLowerCase();
  const prefixed = options.find((o) => lower.length >= 3 && o.toLowerCase().startsWith(lower));
  if (prefixed) return ` (did you mean "${prefixed}"?)`;
  let best: string | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const option of options) {
    const distance = levenshtein(lower, option.toLowerCase());
    if (distance < bestDistance) {
      best = option;
      bestDistance = distance;
    }
  }
  return best !== null && bestDistance <= Math.max(2, Math.floor(input.length / 3))
    ? ` (did you mean "${best}"?)`
    : "";
}

function lastDayOfMonth(year: number, month: number): Date {
  return new Date(Date.UTC(year, month, 0));
}

/** Parses `YYYY-MM-DD` or `YYYY-MM`; a bare month resolves to its first or last day. */
function parseDate(value: unknown, monthResolvesTo: "first" | "last"): Date | null {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
  }
  if (typeof value !== "string") return null;
  const day = DAY.exec(value);
  if (day) {
    const [y, m, d] = [Number(day[1]), Number(day[2]), Number(day[3])];
    const date = new Date(Date.UTC(y, m - 1, d));
    return date.getUTCMonth() === m - 1 && date.getUTCDate() === d ? date : null;
  }
  const month = MONTH.exec(value);
  if (month) {
    const [y, m] = [Number(month[1]), Number(month[2])];
    if (m < 1 || m > 12) return null;
    return monthResolvesTo === "first" ? new Date(Date.UTC(y, m - 1, 1)) : lastDayOfMonth(y, m);
  }
  return null;
}

function httpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

class Validator {
  readonly problems: Problem[] = [];
  readonly placeholders: string[] = [];

  fail(path: Path, message: string): void {
    this.problems.push({ path, message });
  }

  mapping(parent: Record<string, unknown>, key: string, path: Path, required: boolean) {
    const value = parent[key];
    if (value === undefined || value === null) {
      if (required) this.fail([...path, key], "is required");
      return {};
    }
    if (!isRecord(value)) {
      this.fail([...path, key], `expected a mapping, got ${describe(value)}`);
      return {};
    }
    this.unknownKeys(value, [...path, key]);
    return value;
  }

  unknownKeys(record: Record<string, unknown>, path: Path): void {
    const allowed = SHAPE[path.join(".")] ?? [];
    for (const key of Object.keys(record)) {
      if (!allowed.includes(key)) {
        this.fail([...path, key], `unknown key${suggest(key, allowed)}`);
      }
    }
  }

  string(parent: Record<string, unknown>, key: string, path: Path, required: true): string;
  string(parent: Record<string, unknown>, key: string, path: Path, required: false): string | null;
  string(parent: Record<string, unknown>, key: string, path: Path, required: boolean) {
    const value = parent[key];
    const at = [...path, key];
    if (value === undefined || value === null || value === "") {
      if (required) this.fail(at, "is required");
      return required ? "" : null;
    }
    if (typeof value === "number") return String(value);
    if (typeof value !== "string") {
      this.fail(at, `expected text, got ${describe(value)}`);
      return required ? "" : null;
    }
    const trimmed = value.trim();
    if (/\bTODO\b/.test(trimmed)) this.placeholders.push(at.join("."));
    return trimmed;
  }

  email(parent: Record<string, unknown>, key: string, path: Path): string {
    const value = this.string(parent, key, path, true);
    if (value && !EMAIL.test(value)) {
      this.fail([...path, key], `expected an email address, got ${JSON.stringify(value)}`);
    }
    return value;
  }

  boolean(parent: Record<string, unknown>, key: string, path: Path, fallback?: boolean): boolean {
    const value = parent[key];
    if (value === undefined || value === null) {
      if (fallback === undefined) this.fail([...path, key], "is required (true or false)");
      return fallback ?? false;
    }
    if (typeof value !== "boolean") {
      this.fail([...path, key], `expected true or false, got ${describe(value)}`);
      return fallback ?? false;
    }
    return value;
  }

  oneOf<T extends string>(
    parent: Record<string, unknown>,
    key: string,
    path: Path,
    options: readonly T[],
    fallback?: T,
  ): T {
    const value = parent[key];
    const at = [...path, key];
    if (value === undefined || value === null) {
      if (fallback !== undefined) return fallback;
      this.fail(at, `is required, one of: ${options.join(", ")}`);
      return options[0] as T;
    }
    if (!isOneOf(options, value)) {
      const hint = typeof value === "string" ? suggest(value, options) : "";
      this.fail(at, `${describe(value)} is not one of: ${options.join(", ")}${hint}`);
      return fallback ?? (options[0] as T);
    }
    return value;
  }

  list(parent: Record<string, unknown>, key: string, path: Path, fallback?: string[]): string[] {
    const value = parent[key];
    const at = [...path, key];
    if (value === undefined || value === null) {
      if (fallback === undefined) this.fail(at, "is required (a list)");
      return fallback ?? [];
    }
    const items = Array.isArray(value) ? value : [value];
    const out: string[] = [];
    items.forEach((item, index) => {
      if (typeof item !== "string" || item.trim() === "") {
        this.fail([...at, index], `expected text, got ${describe(item)}`);
      } else {
        out.push(item.trim());
      }
    });
    if (out.length === 0 && items.length === 0) this.fail(at, "must not be empty");
    return out;
  }
}

function validate(raw: unknown): {
  config: CraConfig;
  problems: Problem[];
  placeholders: string[];
} {
  const v = new Validator();
  const root = isRecord(raw) ? raw : {};
  if (root !== raw) v.fail([], "the file must contain a YAML mapping with a `product` section");
  v.unknownKeys(root, []);

  const p = v.mapping(root, "product", [], true);
  const pp: Path = ["product"];
  const m = v.mapping(p, "manufacturer", pp, true);
  const mp: Path = ["product", "manufacturer"];
  const s = v.mapping(p, "securityContact", pp, true);
  const sp: Path = ["product", "securityContact"];

  const website = v.string(m, "website", mp, false);
  if (website && !/^https?:\/\//.test(website)) {
    v.fail([...mp, "website"], `expected an http(s) URL, got ${JSON.stringify(website)}`);
  }
  const contactUrl = v.string(s, "url", sp, false);
  if (contactUrl && !httpsUrl(contactUrl)) {
    v.fail([...sp, "url"], "must be an https:// URL (RFC 9116 requires https for web URIs)");
  }
  let pgpKey = v.string(s, "pgpKey", sp, false);
  if (pgpKey) {
    if (FINGERPRINT.test(pgpKey)) {
      pgpKey = `openpgp4fpr:${pgpKey.replace(/\s+/g, "").toLowerCase()}`;
    } else if (!httpsUrl(pgpKey) && !pgpKey.startsWith("openpgp4fpr:")) {
      v.fail([...sp, "pgpKey"], "must be an https:// URL of the key or a 40-hex-digit fingerprint");
    }
  }

  const monetisation = v.list(p, "monetisation", pp);
  monetisation.forEach((item, index) => {
    if (!isOneOf(MONETISATION, item)) {
      v.fail(
        [...pp, "monetisation", index],
        `"${item}" is not one of: ${MONETISATION.join(", ")}${suggest(item, MONETISATION)}`,
      );
    }
  });
  if (monetisation.includes("none") && monetisation.length > 1) {
    v.fail([...pp, "monetisation"], '"none" cannot be combined with other values');
  }

  let placedOnMarketAt: Date | null = null;
  if (p.placedOnMarketAt !== undefined && p.placedOnMarketAt !== null) {
    placedOnMarketAt = parseDate(p.placedOnMarketAt, "first");
    if (!placedOnMarketAt) {
      v.fail(
        [...pp, "placedOnMarketAt"],
        `expected YYYY-MM-DD or YYYY-MM, got ${describe(p.placedOnMarketAt)}`,
      );
    }
  }
  const supportEndsAt = parseDate(p.supportEndsAt, "last");
  if (!supportEndsAt) {
    v.fail(
      [...pp, "supportEndsAt"],
      p.supportEndsAt === undefined
        ? "is required: the end of the support period, YYYY-MM (Art. 13(8), 13(19))"
        : `expected YYYY-MM or YYYY-MM-DD, got ${describe(p.supportEndsAt)}`,
    );
  }
  let expectedUseYears: number | null = null;
  if (p.expectedUseYears !== undefined && p.expectedUseYears !== null) {
    if (typeof p.expectedUseYears !== "number" || !(p.expectedUseYears > 0)) {
      v.fail([...pp, "expectedUseYears"], `expected a positive number of years`);
    } else {
      expectedUseYears = p.expectedUseYears;
    }
  }

  const languages = v.list(p, "languages", pp);
  languages.forEach((tag, index) => {
    if (!LANGUAGE.test(tag)) {
      v.fail([...pp, "languages", index], `"${tag}" is not a language tag such as en, de or pt-BR`);
    }
  });

  const sbom = v.mapping(root, "sbom", [], false);
  const scan = v.mapping(root, "scan", [], false);
  const output = v.mapping(root, "output", [], false);
  const paths = v.list(sbom, "paths", ["sbom"], ["."]);
  for (const [index, path] of paths.entries()) {
    if (path.startsWith("/")) v.fail(["sbom", "paths", index], "must be relative to the project");
  }
  const outputDir = v.string(output, "dir", ["output"], false) ?? "docs/compliance";
  if (outputDir.startsWith("/") || outputDir.split(/[\\/]/).includes("..")) {
    v.fail(["output", "dir"], "must be a path inside the project");
  }

  const config: CraConfig = {
    product: {
      name: v.string(p, "name", pp, true),
      version: v.string(p, "version", pp, false),
      manufacturer: {
        name: v.string(m, "name", mp, true),
        address: v.string(m, "address", mp, true),
        email: v.email(m, "email", mp),
        website,
      },
      distribution: v.oneOf(p, "distribution", pp, DISTRIBUTION_MODELS),
      coreFunction: v.oneOf(p, "coreFunction", pp, CORE_FUNCTIONS),
      availableInEu: v.boolean(p, "availableInEu", pp, true),
      isFoss: v.boolean(p, "isFoss", pp),
      isOpenSourceSteward: v.boolean(p, "isOpenSourceSteward", pp, false),
      publicTechnicalDocs: v.boolean(p, "publicTechnicalDocs", pp, false),
      monetisation: monetisation.filter((x) => isOneOf(MONETISATION, x)),
      placedOnMarketAt,
      substantialModificationAfterApplication: v.boolean(
        p,
        "substantialModificationAfterApplication",
        pp,
        false,
      ),
      intendedPurpose: v.string(p, "intendedPurpose", pp, true),
      supportEndsAt: supportEndsAt ?? new Date(0),
      expectedUseYears,
      securityContact: { email: v.email(s, "email", sp), url: contactUrl, pgpKey },
      languages,
    },
    sbom: {
      paths,
      includeDev: v.boolean(sbom, "includeDev", ["sbom"], false),
      generator: v.oneOf(sbom, "generator", ["sbom"], SBOM_GENERATORS, "auto"),
    },
    scan: { failOn: v.oneOf(scan, "failOn", ["scan"], FAIL_ON, "kev") },
    output: { dir: outputDir },
  };
  if (placedOnMarketAt && supportEndsAt && supportEndsAt.getTime() <= placedOnMarketAt.getTime()) {
    v.fail(["product", "supportEndsAt"], "must be after placedOnMarketAt");
  }
  return { config, problems: v.problems, placeholders: v.placeholders };
}

/** Parses and validates cra.yml text; `file` is only used in messages. */
export function parseConfig(text: string, file: string): LoadedConfig {
  const lineCounter = new LineCounter();
  const doc = parseDocument(text, { lineCounter, prettyErrors: false, uniqueKeys: true });
  if (doc.errors.length > 0) {
    throw new ConfigError(
      file,
      doc.errors.map((e) => {
        const pos = lineCounter.linePos(e.pos[0]);
        return `${file}:${pos.line}:${pos.col} ${e.message.split("\n")[0]}`;
      }),
    );
  }
  const { config, problems, placeholders } = validate(doc.toJS());
  if (problems.length > 0) {
    throw new ConfigError(
      file,
      problems.map(({ path, message }) => {
        // Point at the offending node, or the closest ancestor that exists.
        for (let depth = path.length; depth >= 0; depth--) {
          const node = depth === 0 ? doc.contents : doc.getIn(path.slice(0, depth), true);
          if (isNode(node) && node.range && (depth === path.length || isMap(node))) {
            const pos = lineCounter.linePos(node.range[0]);
            return `${file}:${pos.line}:${pos.col} ${path.join(".") || "(root)"} ${message}`;
          }
        }
        return `${path.join(".") || "(root)"} ${message}`;
      }),
    );
  }
  return { config, placeholders };
}

export async function loadConfig(path: string, displayName: string): Promise<LoadedConfig> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if (errnoCode(error) === "ENOENT") {
      throw new UsageError(
        `${displayName} not found: run \`cra init\` to create one, or pass --config <path>`,
      );
    }
    throw error;
  }
  return parseConfig(text, displayName);
}
