import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../src/config";
import { bomPackages, buildBom, licenseChoices, serializeBom } from "../src/sbom/cyclonedx";
import { buildInventory } from "../src/sbom/discover";
import { VALID } from "./helpers";

const product = parseConfig(VALID, "cra.yml").config.product;
const inventory = buildInventory(join(import.meta.dirname, "fixtures", "npm"), ["."], false);
const NOW = new Date("2026-10-02T09:00:00Z");
/** The pattern from the CycloneDX 1.6 JSON schema. */
const SERIAL = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("CycloneDX 1.6 output", () => {
  const bom = buildBom(inventory, product, "2.3.0", NOW);

  it("has the document envelope and the product as metadata.component", () => {
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.version).toBe(1);
    expect(bom.serialNumber).toMatch(SERIAL);
    expect(bom.metadata.timestamp).toBe("2026-10-02T09:00:00Z");
    expect(bom.metadata.tools.components.map((t) => t.name)).toEqual(["cra-kit"]);
    expect(bom.metadata.component).toMatchObject({
      type: "application",
      "bom-ref": "Acme Backup@2.3.0",
      name: "Acme Backup",
      version: "2.3.0",
      manufacturer: { name: "Acme Software sp. z o.o.", url: ["https://acme.example"] },
    });
  });

  it("lists components with purls, scopes, hashes and licenses", () => {
    const util = bom.components.find((c) => c.purl === "pkg:npm/%40scope/util@2.1.0");
    expect(util).toMatchObject({
      type: "library",
      "bom-ref": "pkg:npm/%40scope/util@2.1.0",
      group: "@scope",
      name: "util",
      version: "2.1.0",
      scope: "required",
      licenses: [{ expression: "(MIT OR Apache-2.0)" }],
    });
    expect(util?.hashes?.[0]?.alg).toBe("SHA-512");
    expect(bom.components.find((c) => c.name === "fsevents")?.scope).toBe("optional");
    expect(bom.components.map((c) => c.purl)).toEqual(
      [...bom.components.map((c) => c.purl)].sort(),
    );
  });

  it("records the dependency graph, starting from the product", () => {
    expect(bom.dependencies[0]).toEqual({
      ref: "Acme Backup@2.3.0",
      dependsOn: [
        "pkg:npm/%40scope/util@2.1.0",
        "pkg:npm/express@4.18.2",
        "pkg:npm/fsevents@2.3.3",
        "pkg:npm/left-pad@1.3.0",
      ],
    });
    expect(bom.dependencies).toContainEqual({
      ref: "pkg:npm/express@4.18.2",
      dependsOn: ["pkg:npm/debug@2.6.9", "pkg:npm/qs@6.11.0"],
    });
    expect(bom.dependencies).toHaveLength(bom.components.length + 1);
  });

  it("is byte-identical for identical input and a new serial for a new generation time", () => {
    expect(serializeBom(buildBom(inventory, product, "2.3.0", NOW))).toBe(serializeBom(bom));
    const later = buildBom(inventory, product, "2.3.0", new Date("2026-10-03T09:00:00Z"));
    expect(later.serialNumber).toMatch(SERIAL);
    expect(later.serialNumber).not.toBe(bom.serialNumber);
  });

  it("maps license strings to SPDX ids, names or a single expression", () => {
    expect(licenseChoices(["mit", "Custom EULA"])).toEqual([
      { license: { id: "MIT" } },
      { license: { name: "Custom EULA" } },
    ]);
    expect(licenseChoices(["MIT", "Apache-2.0 WITH LLVM-exception"])).toEqual([
      { expression: "MIT OR (Apache-2.0 WITH LLVM-exception)" },
    ]);
  });

  it("reads packages back from any CycloneDX document, nested components included", () => {
    const external = {
      bomFormat: "CycloneDX",
      components: [
        {
          type: "library",
          name: "a",
          purl: "pkg:cargo/a@1.0.0",
          components: [{ type: "library", name: "b", purl: "pkg:golang/github.com/x/b@v2.0.0" }],
        },
        { type: "file", name: "no-purl" },
      ],
    };
    expect(bomPackages(external)).toEqual([
      { purl: "pkg:cargo/a@1.0.0", type: "cargo", name: "a", version: "1.0.0", scope: null },
      {
        purl: "pkg:golang/github.com/x/b@v2.0.0",
        type: "golang",
        name: "github.com/x/b",
        version: "v2.0.0",
        scope: null,
      },
    ]);
  });
});
