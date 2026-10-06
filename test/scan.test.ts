import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NetworkError } from "../src/errors";
import { asArray, asRecord } from "../src/guards";
import type { BomPackage } from "../src/sbom/cyclonedx";
import { cvss2BaseScore, cvss3BaseScore } from "../src/scan/cvss";
import { exceedsThreshold, type Finding, severityOf } from "../src/scan/findings";
import { toOsvVuln } from "../src/scan/osv";
import { runScan } from "../src/scan/scan";
import { failingFetch, mockFetch, osvRoutes } from "./helpers";

const NOW = new Date("2026-10-02T09:00:00Z");
const PACKAGES: BomPackage[] = [
  {
    purl: "pkg:npm/lodash@4.17.20",
    type: "npm",
    name: "lodash",
    version: "4.17.20",
    scope: "required",
  },
  { purl: "pkg:npm/ms@2.1.3", type: "npm", name: "ms", version: "2.1.3", scope: "required" },
  {
    purl: "pkg:pypi/requests@2.19.0",
    type: "pypi",
    name: "requests",
    version: "2.19.0",
    scope: "required",
  },
  {
    purl: "pkg:npm/unversioned",
    type: "npm",
    name: "unversioned",
    version: null,
    scope: "required",
  },
];
const cacheDir = () => mkdtempSync(join(tmpdir(), "cra-cache-"));

describe("CVSS base scores", () => {
  it("computes v3.1 and v3.0 vectors per the FIRST formulas", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")).toBe(9.9);
    expect(cvss3BaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")).toBe(5.5);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")).toBe(7.2);
    expect(cvss3BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(
      cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:X/AC:L")).toBeNull();
  });

  it("computes v2 vectors", () => {
    expect(cvss2BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBe(7.5);
    expect(cvss2BaseScore("AV:N/AC:M/Au:N/C:N/I:P/A:N")).toBe(4.3);
  });

  it("prefers CVSS v3, then the database rating, then CVSS v2", () => {
    const base = { id: "X-1", affected: [] };
    expect(
      severityOf(
        toOsvVuln({
          ...base,
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
          database_specific: { severity: "LOW" },
        }) ?? fail(),
      ),
    ).toMatchObject({ severity: "critical", score: 9.8, source: "CVSS_V3" });
    expect(
      severityOf(
        toOsvVuln({
          ...base,
          severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }],
          database_specific: { severity: "MODERATE" },
        }) ?? fail(),
      ),
    ).toMatchObject({
      severity: "medium",
      score: null,
      source: "database",
      vector: "CVSS:4.0/AV:N",
    });
    expect(
      severityOf(
        toOsvVuln({
          ...base,
          severity: [{ type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:P/I:P/A:P" }],
        }) ?? fail(),
      ),
    ).toMatchObject({ severity: "high", score: 7.5, source: "CVSS_V2" });
    expect(severityOf(toOsvVuln(base) ?? fail()).severity).toBe("unknown");
  });
});

function fail(): never {
  throw new Error("expected an OSV record");
}

describe("OSV and KEV scan", () => {
  it("queries by purl, follows pagination, merges aliases and flags KEV entries", async () => {
    const fetch = mockFetch(osvRoutes());
    const report = await runScan(PACKAGES, {
      fetch,
      cacheDir: cacheDir(),
      now: NOW,
      offline: false,
      retryDelayMs: 0,
    });

    const batches = fetch.requests.filter((r) => r.url.endsWith("/v1/querybatch"));
    expect(batches[0]?.body).toEqual({
      queries: [
        { package: { purl: "pkg:npm/lodash@4.17.20" } },
        { package: { purl: "pkg:npm/ms@2.1.3" } },
        { package: { purl: "pkg:pypi/requests@2.19.0" } },
      ],
    });
    expect(batches[1]?.body).toEqual({
      queries: [{ package: { purl: "pkg:npm/lodash@4.17.20" }, page_token: "page-2" }],
    });

    expect(report.status).toBe("complete");
    expect(report.components).toEqual({ total: 4, queried: 3, unchecked: 1 });
    expect(
      report.findings.map((f) => [
        f.id,
        f.package.name,
        f.severity,
        f.score,
        f.kev?.cve ?? null,
        f.fixedVersions,
      ]),
    ).toEqual([
      ["GHSA-35jh-r3h4-6jhm", "lodash", "high", 7.2, "CVE-2021-23337", ["4.17.21"]],
      ["GHSA-x84v-xcm2-53pg", "requests", "high", 7.5, null, ["2.20.0"]],
      ["GHSA-29mw-wpgm-hmr9", "lodash", "medium", 5.3, null, ["4.17.21"]],
    ]);
    expect(report.findings[1]?.aliases).toEqual(["CVE-2018-18074", "PYSEC-2018-28"]);
    expect(report.summary).toEqual({
      total: 3,
      kev: 1,
      critical: 0,
      high: 2,
      medium: 1,
      low: 0,
      unknown: 0,
    });
    expect(report.kevCatalog).toEqual({
      version: "2026.10.01",
      released: "2026-10-01T15:00:00.0000Z",
    });
  });

  it("serves --offline runs from the cache and never touches the network", async () => {
    const dir = cacheDir();
    const online = await runScan(PACKAGES, {
      fetch: mockFetch(osvRoutes()),
      cacheDir: dir,
      now: NOW,
      offline: false,
      retryDelayMs: 0,
    });
    // A day later the cache is stale, but offline runs still use it.
    const offline = await runScan(PACKAGES, {
      fetch: failingFetch,
      cacheDir: dir,
      now: new Date("2026-10-03T09:00:00Z"),
      offline: true,
    });
    expect(offline.findings).toEqual(online.findings);
    expect(offline.status).toBe("complete");
  });

  it("re-fetches only stale entries when online", async () => {
    const dir = cacheDir();
    await runScan(PACKAGES, {
      fetch: mockFetch(osvRoutes()),
      cacheDir: dir,
      now: NOW,
      offline: false,
      retryDelayMs: 0,
    });
    const fresh = mockFetch(osvRoutes());
    await runScan(PACKAGES, {
      fetch: fresh,
      cacheDir: dir,
      now: new Date(NOW.getTime() + 60 * 60 * 1000),
      offline: false,
      retryDelayMs: 0,
    });
    expect(fresh.requests).toEqual([]);
  });

  it("reports a skipped scan when offline without a cache", async () => {
    const report = await runScan(PACKAGES, {
      fetch: failingFetch,
      cacheDir: cacheDir(),
      now: NOW,
      offline: true,
    });
    expect(report.status).toBe("skipped");
    expect(report.findings).toEqual([]);
    expect(report.notes.join(" ")).toContain("run once without --offline");
  });

  it("fails with a network error when OSV is unreachable online", async () => {
    await expect(
      runScan(PACKAGES, {
        fetch: failingFetch,
        cacheDir: cacheDir(),
        now: NOW,
        offline: false,
        retryDelayMs: 0,
      }),
    ).rejects.toBeInstanceOf(NetworkError);
  });

  it("splits large SBOMs into batches of 500 purls", async () => {
    const many: BomPackage[] = Array.from({ length: 1200 }, (_, i) => ({
      purl: `pkg:npm/pkg-${i}@1.0.0`,
      type: "npm",
      name: `pkg-${i}`,
      version: "1.0.0",
      scope: "required",
    }));
    const fetch = mockFetch(osvRoutes());
    await runScan(many, { fetch, cacheDir: cacheDir(), now: NOW, offline: false, retryDelayMs: 0 });
    const sizes = fetch.requests
      .filter((r) => r.url.endsWith("/v1/querybatch"))
      .map((r) => asArray(asRecord(r.body).queries).length);
    expect(sizes).toEqual([500, 500, 200]);
  });
});

describe("failOn policy", () => {
  const finding = (severity: Finding["severity"], kev: boolean): Finding => ({
    id: "GHSA-test",
    aliases: [],
    summary: "",
    package: { purl: "pkg:npm/x@1.0.0", name: "x", version: "1.0.0", ecosystem: "npm" },
    severity,
    score: null,
    vector: null,
    severitySource: null,
    kev: kev
      ? { cve: "CVE-1", dateAdded: "", dueDate: "", knownRansomwareCampaignUse: "Unknown" }
      : null,
    fixedVersions: [],
    url: "",
  });

  it("fails on KEV at every level but none, and on severity at or above the level", () => {
    const kevLow = [finding("low", true)];
    const critical = [finding("critical", false)];
    const high = [finding("high", false)];
    expect(exceedsThreshold(kevLow, "kev")).toBe(true);
    expect(exceedsThreshold(kevLow, "critical")).toBe(true);
    expect(exceedsThreshold(kevLow, "none")).toBe(false);
    expect(exceedsThreshold(critical, "kev")).toBe(false);
    expect(exceedsThreshold(critical, "critical")).toBe(true);
    expect(exceedsThreshold(high, "critical")).toBe(false);
    expect(exceedsThreshold(high, "high")).toBe(true);
    expect(exceedsThreshold([finding("medium", false)], "high")).toBe(false);
    expect(exceedsThreshold([finding("unknown", false)], "high")).toBe(false);
  });
});
