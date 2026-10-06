import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../src/config";
import { type DocsInput, TODO, VendorBlocks } from "../src/docs/common";
import { declarationOfConformity } from "../src/docs/declaration";
import { writeDocs } from "../src/docs/generate";
import { supportPeriod } from "../src/docs/support";
import { reportingRunbook, securityTxt } from "../src/docs/vulnerability";
import { scopeAnswers } from "../src/project";
import { assessCraScope } from "../src/rules";
import type { ScanReport } from "../src/scan/scan";
import { VALID } from "./helpers";

function docsInput(yaml = VALID, overrides: Partial<DocsInput> = {}): DocsInput {
  const product = parseConfig(yaml, "cra.yml").config.product;
  const packages = [
    {
      purl: "pkg:npm/lodash@4.17.20",
      type: "npm",
      name: "lodash",
      version: "4.17.20",
      scope: "required",
    },
  ];
  return {
    product,
    version: "2.3.0",
    releaseDate: new Date("2028-01-15T00:00:00Z"),
    now: new Date("2028-01-15T10:30:00Z"),
    scope: assessCraScope(scopeAnswers(product)),
    sbom: {
      sha256: "a".repeat(64),
      serialNumber: "urn:uuid:00000000-0000-5000-8000-000000000000",
      generator: "builtin",
      lockfiles: ["package-lock.json"],
      packages,
      direct: packages,
    },
    scan: null,
    scanError: "offline",
    placeholders: [],
    ...overrides,
  };
}

const KEV_SCAN: ScanReport = {
  status: "complete",
  notes: [],
  components: { total: 1, queried: 1, unchecked: 0 },
  summary: { total: 1, kev: 1, critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
  findings: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      summary: "Command Injection in lodash",
      package: {
        purl: "pkg:npm/lodash@4.17.20",
        name: "lodash",
        version: "4.17.20",
        ecosystem: "npm",
      },
      severity: "high",
      score: 7.2,
      vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
      severitySource: "CVSS_V3",
      kev: {
        cve: "CVE-2021-23337",
        dateAdded: "2026-09-30",
        dueDate: "2026-10-21",
        knownRansomwareCampaignUse: "Unknown",
      },
      fixedVersions: ["4.17.21"],
      url: "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
    },
  ],
  kevCatalog: { version: "2028.01.14", released: "2028-01-14T15:00:00Z" },
};

const tempDir = () => mkdtempSync(join(tmpdir(), "cra-docs-"));
const fresh = new VendorBlocks(null);

describe("security.txt", () => {
  it("has the RFC 9116 fields, with Expires under a year away", () => {
    const text = securityTxt(docsInput());
    expect(text).toContain("Contact: mailto:security@acme.example\n");
    expect(text).toContain("Expires: 2029-01-01T00:00:00Z\n");
    expect(text).toContain("Encryption: openpgp4fpr:abcd1234abcd1234abcd1234abcd1234abcd1234\n");
    expect(text).toContain("Policy: https://acme.example/security\n");
    expect(text).toContain("Preferred-Languages: en, pl\n");
  });
});

describe("EU declaration of conformity", () => {
  it("lists the product and manufacturer, and stays an unsigned draft", () => {
    const text = declarationOfConformity(docsInput(), fresh);
    expect(text).toContain("- Name: Acme Backup");
    expect(text).toContain("- Version: 2.3.0");
    expect(text).toContain("- Name: Acme Software sp. z o.o.");
    expect(text).toContain("- Address: ul. Prosta 1, 00-001 Warszawa, Poland");
    expect(text).toContain("issued under the sole responsibility of the manufacturer");
    expect(text).toContain("no legal effect until the manufacturer");
    expect(text).toContain("Not applicable: internal control (module A)");
    expect(text).toContain(`Signature: ${TODO}`);
  });

  it("asks for the notified body when the route needs one", () => {
    const text = declarationOfConformity(
      docsInput(
        VALID.replace(
          "coreFunction: none_of_the_above",
          "coreFunction: firewall_or_intrusion_detection",
        ),
      ),
      fresh,
    );
    expect(text).toContain(`${TODO}: name and number of the notified body`);
    expect(text).toContain("(Art. 32(3))");
  });
});

describe("support period", () => {
  it("states the end month and computes Art. 13(9) availability with core", () => {
    const text = supportPeriod(
      docsInput(VALID.replace("supportEndsAt: 2032-12", "supportEndsAt: 2033-06")),
      fresh,
    );
    expect(text).toContain("provided until the end of **June 2033**");
    expect(text).toContain("| This release (2.3.0) | 2028-01-15 | 2038-01-15 |");
    expect(text).toContain("| Last day of support | 2033-06-30 | 2043-06-30 |");
    expect(text).toContain("**Check: passes.**");
    expect(text).toContain("until at least 2038-01-15");
  });

  it("flags a support period shorter than five years without justification", () => {
    const text = supportPeriod(
      docsInput(VALID.replace("supportEndsAt: 2032-12", "supportEndsAt: 2030-06")),
      fresh,
    );
    expect(text).toContain("**Check: fails.** The support period is shorter than 5 years");
  });
});

describe("reporting runbook", () => {
  it("works the Art. 14 example through core's clocks and raises KEV findings", () => {
    const text = reportingRunbook(docsInput(undefined, { scan: KEV_SCAN, scanError: null }), fresh);
    expect(text).toContain("| Early warning | 2027-03-16T09:00:00Z |");
    expect(text).toContain("| Notification | 2027-03-18T09:00:00Z |");
    expect(text).toContain("| Final report | 2027-04-02T16:00:00Z |");
    expect(text).toContain("| Final report | 2027-04-17T10:00:00Z |");
    expect(text).toContain(
      "found 1 vulnerability listed in the CISA KEV catalog (GHSA-35jh-r3h4-6jhm in lodash)",
    );
  });
});

describe("writeDocs", () => {
  it("writes every record, links them from index.md and leaves other files alone", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "notes.md"), "vendor notes\n");
    const { files, openItems } = await writeDocs(dir, docsInput(), "{}\n", null);
    expect(files).toEqual([
      "technical-documentation.md",
      "risk-assessment.md",
      "declaration-of-conformity.md",
      "vulnerability-handling.md",
      "support-period.md",
      "user-information.md",
      "reporting-runbook.md",
      "security.txt",
      "sbom.cdx.json",
      "scan.json",
      "index.md",
    ]);
    expect(readFileSync(join(dir, "notes.md"), "utf8")).toBe("vendor notes\n");
    const index = readFileSync(join(dir, "index.md"), "utf8");
    for (const file of files.filter((f) => f !== "index.md")) expect(index).toContain(`](${file})`);
    expect(index).toContain("| Generated | 2028-01-15T10:30:00Z by cra ");
    expect(index).toContain(`| SBOM SHA-256 | \`${"a".repeat(64)}\` |`);
    expect(index).toContain(`${openItems} open items are marked`);
    expect(JSON.parse(readFileSync(join(dir, "scan.json"), "utf8"))).toMatchObject({
      status: "error",
      notes: ["offline"],
    });
  });

  it("keeps the manufacturer's sections on regeneration and reflects them in the overview", async () => {
    const dir = tempDir();
    const first = await writeDocs(dir, docsInput(), "{}\n", null);
    const path = join(dir, "risk-assessment.md");
    const completed = readFileSync(path, "utf8").replace(
      /<!-- cra:vendor annex-i-2a -->\n[\s\S]*?\n<!-- cra:end annex-i-2a -->/,
      "<!-- cra:vendor annex-i-2a -->\n- Applicable: yes\n- Status: implemented\n- How: dependency updates before every release\n<!-- cra:end annex-i-2a -->",
    );
    writeFileSync(path, completed);
    const second = await writeDocs(dir, docsInput(undefined, { version: "2.4.0" }), "{}\n", null);
    const text = readFileSync(path, "utf8");
    expect(text).toContain("- How: dependency updates before every release");
    expect(text).toContain("| (2)(a) No known exploitable vulnerabilities | yes | implemented |");
    expect(text).toContain(
      "| (2)(b) Secure by default configuration | not assessed | not assessed |",
    );
    expect(text).toContain("Acme Backup 2.4.0");
    expect(second.openItems).toBe(first.openItems - 1);
  });

  it("changes only index.md when nothing but the generation time changes", async () => {
    const a = tempDir();
    const b = tempDir();
    await writeDocs(a, docsInput(), "{}\n", KEV_SCAN);
    await writeDocs(
      b,
      docsInput(undefined, { now: new Date("2028-01-20T08:00:00Z") }),
      "{}\n",
      KEV_SCAN,
    );
    const differing = readdirSync(a).filter(
      (f) => readFileSync(join(a, f), "utf8") !== readFileSync(join(b, f), "utf8"),
    );
    expect(differing).toEqual(["index.md"]);
  });

  it("marks out-of-scope products in every document and never uses typographic dashes", async () => {
    const dir = tempDir();
    await writeDocs(
      dir,
      docsInput(VALID.replace("[subscription_or_licence]", "[none]")),
      "{}\n",
      KEV_SCAN,
    );
    for (const file of readdirSync(dir)) {
      const text = readFileSync(join(dir, file), "utf8");
      expect(text, file).not.toMatch(/[\u2013\u2014]/);
      if (file.endsWith(".md") && file !== "index.md")
        expect(text, file).toContain("Scope triage: out of scope.");
    }
  });
});
