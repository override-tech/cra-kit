import { createHash } from "node:crypto";
import type { ProductConfig } from "../config";
import { compareStrings, isoDateTime } from "../format";
import { asArray, asRecord, asString } from "../guards";
import { CLI_VERSION } from "../version";
import type { Component, Inventory } from "./model";
import { parsePurl } from "./purl";

export interface CycloneDxComponent {
  type: string;
  "bom-ref"?: string;
  group?: string;
  name: string;
  version?: string;
  description?: string;
  scope?: string;
  hashes?: Array<{ alg: string; content: string }>;
  licenses?: Array<{ license: { id: string } | { name: string } } | { expression: string }>;
  purl?: string;
  supplier?: unknown;
  manufacturer?: unknown;
  properties?: Array<{ name: string; value: string }>;
  components?: CycloneDxComponent[];
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    lifecycles?: Array<{ phase: string }>;
    tools: { components: CycloneDxComponent[] };
    component: CycloneDxComponent;
    manufacturer?: unknown;
    properties?: Array<{ name: string; value: string }>;
  };
  components: CycloneDxComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
}

/** SPDX identifiers common in package registries; others are emitted as names or expressions. */
const SPDX_IDS = new Set(
  (
    "0BSD AFL-3.0 AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0 Artistic-2.0 " +
    "BlueOak-1.0.0 BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-3-Clause-Clear BSL-1.0 CC-BY-3.0 " +
    "CC-BY-4.0 CC-BY-SA-4.0 CC0-1.0 CDDL-1.0 CDDL-1.1 EPL-1.0 EPL-2.0 EUPL-1.1 EUPL-1.2 GPL-2.0 " +
    "GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later ISC LGPL-2.0 " +
    "LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 " +
    "LGPL-3.0-only LGPL-3.0-or-later MIT MIT-0 MPL-1.1 MPL-2.0 MS-PL NCSA OFL-1.1 OpenSSL " +
    "PHP-3.01 PostgreSQL Python-2.0 Ruby Unicode-3.0 Unicode-DFS-2016 Unlicense UPL-1.0 WTFPL " +
    "X11 Zlib ZPL-2.1"
  ).split(" "),
);
const SPDX_BY_LOWER = new Map([...SPDX_IDS].map((id) => [id.toLowerCase(), id]));
const isExpression = (s: string) => /\s(OR|AND|WITH)\s|[()]/i.test(s);

export function licenseChoices(licenses: string[]): CycloneDxComponent["licenses"] {
  if (licenses.length === 0) return undefined;
  if (licenses.some(isExpression)) {
    // A licenses array may hold one expression or several licenses, never both.
    const expression =
      licenses.length === 1
        ? (licenses[0] ?? "")
        : licenses.map((l) => (isExpression(l) ? `(${l})` : l)).join(" OR ");
    return [{ expression }];
  }
  return licenses.map((l) => {
    const id = SPDX_BY_LOWER.get(l.toLowerCase());
    return { license: id ? { id } : { name: l } };
  });
}

function componentJson(c: Component): CycloneDxComponent {
  let group: string | undefined;
  let name = c.name;
  if ((c.ecosystem === "npm" && name.startsWith("@")) || c.ecosystem === "composer") {
    const slash = name.indexOf("/");
    if (slash > 0) {
      group = name.slice(0, slash);
      name = name.slice(slash + 1);
    }
  }
  return {
    type: "library",
    "bom-ref": c.purl,
    ...(group ? { group } : {}),
    name,
    ...(c.version ? { version: c.version } : {}),
    scope: c.scope,
    ...(c.hashes.length > 0 ? { hashes: c.hashes } : {}),
    ...(c.licenses.length > 0 ? { licenses: licenseChoices(c.licenses) } : {}),
    purl: c.purl,
    properties: c.sources.map((value) => ({ name: "cra-kit:lockfile", value })),
  };
}

export function productRef(product: ProductConfig, version: string): string {
  return `${product.name}@${version}`;
}

export function productComponent(product: ProductConfig, version: string): CycloneDxComponent {
  const organization = {
    name: product.manufacturer.name,
    ...(product.manufacturer.website ? { url: [product.manufacturer.website] } : {}),
    contact: [{ email: product.manufacturer.email }],
  };
  return {
    type:
      product.distribution === "firmware_or_device"
        ? "firmware"
        : product.distribution === "library_or_package"
          ? "library"
          : "application",
    "bom-ref": productRef(product, version),
    name: product.name,
    version,
    description: product.intendedPurpose,
    supplier: organization,
    manufacturer: organization,
  };
}

export const CRA_KIT_TOOL: CycloneDxComponent = {
  type: "application",
  name: "cra-kit",
  version: CLI_VERSION,
};

/**
 * RFC 4122 version 5 UUID over the BOM content and timestamp: unique per
 * generation (as CycloneDX asks) yet reproducible for identical input.
 */
export function deterministicSerial(content: string): string {
  const namespace = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex"); // RFC 4122 URL namespace
  const bytes = createHash("sha1").update(namespace).update(content).digest().subarray(0, 16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function buildBom(
  inventory: Inventory,
  product: ProductConfig,
  version: string,
  now: Date,
): CycloneDxBom {
  const ref = productRef(product, version);
  const components = inventory.components.map(componentJson);
  const dependencies = [
    { ref, dependsOn: inventory.direct },
    ...inventory.components
      .filter((c) => c.graphKnown)
      .map((c) => ({ ref: c.purl, dependsOn: c.dependsOn })),
  ];
  const timestamp = isoDateTime(now);
  const body = {
    metadata: {
      timestamp,
      lifecycles: [{ phase: "pre-build" }],
      tools: { components: [CRA_KIT_TOOL] },
      component: productComponent(product, version),
      properties: inventory.lockfiles.map((value) => ({ name: "cra-kit:lockfile", value })),
    },
    components,
    dependencies,
  };
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: deterministicSerial(JSON.stringify(body)),
    version: 1,
    ...body,
  };
}

export interface BomPackage {
  purl: string;
  type: string;
  name: string;
  version: string | null;
  scope: string | null;
}

/** Third-party packages with a purl from any CycloneDX JSON document (ours, Syft's, others). */
export function bomPackages(bom: unknown): BomPackage[] {
  const out = new Map<string, BomPackage>();
  const visit = (list: unknown) => {
    for (const raw of asArray(list)) {
      const c = asRecord(raw);
      const purl = asString(c.purl);
      const parsed = purl ? parsePurl(purl) : null;
      if (purl && parsed && !out.has(purl)) {
        out.set(purl, { purl, ...parsed, scope: asString(c.scope) ?? null });
      }
      visit(c.components);
    }
  };
  visit(asRecord(bom).components);
  return [...out.values()].sort((a, b) => compareStrings(a.purl, b.purl));
}

/** Stable serialisation: two-space indent and a trailing newline. */
export function serializeBom(bom: CycloneDxBom): string {
  return `${JSON.stringify(bom, null, 2)}\n`;
}
