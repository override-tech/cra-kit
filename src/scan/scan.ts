import { compareStrings } from "../format";
import type { BomPackage } from "../sbom/cyclonedx";
import { OSV_ECOSYSTEM } from "../sbom/purl";
import { CLI_VERSION } from "../version";
import { buildFindings, type Finding, type Summary, summarize } from "./findings";
import { KEV_URL, loadKev } from "./kev";
import { FeedCache, type FetchLike } from "./net";
import { fetchVulns, OSV_API, queryOsv } from "./osv";

export type ScanStatus = "complete" | "partial" | "skipped";

export interface ScanReport {
  status: ScanStatus;
  notes: string[];
  components: { total: number; queried: number; unchecked: number };
  summary: Summary;
  findings: Finding[];
  /** Reported in index.md only: it changes daily and would make scan.json noisy. */
  kevCatalog: { version: string; released: string } | null;
}

export interface ScanOptions {
  fetch: FetchLike;
  cacheDir: string;
  now: Date;
  offline: boolean;
  osvApi?: string;
  kevUrl?: string;
  retryDelayMs?: number;
}

/** Matches SBOM packages against OSV and flags the ones listed in CISA KEV. */
export async function runScan(packages: BomPackage[], options: ScanOptions): Promise<ScanReport> {
  const cache = new FeedCache(options.cacheDir, options.now);
  const net = { fetch: options.fetch, retryDelayMs: options.retryDelayMs ?? 1000 };
  const osv = { net, cache, offline: options.offline, api: options.osvApi ?? OSV_API };
  const notes: string[] = [];

  const queryable = packages.filter(
    (p) => p.version !== null && OSV_ECOSYSTEM[p.type] !== undefined,
  );
  const skipped = packages.length - queryable.length;
  if (skipped > 0) {
    notes.push(
      `${skipped} component(s) without a version or with an unsupported package type were not checked`,
    );
  }
  const { ids, unchecked } = await queryOsv(
    queryable.map((p) => p.purl),
    osv,
  );
  const allIds = [...new Set([...ids.values()].flat())].sort(compareStrings);
  const { vulns, missing } = await fetchVulns(allIds, osv);
  const kev = await loadKev({
    net,
    cache,
    offline: options.offline,
    url: options.kevUrl ?? KEV_URL,
  });

  if (unchecked.length > 0) {
    notes.push(
      `${unchecked.length} component(s) have no cached OSV result; run once without --offline to check them`,
    );
  }
  if (missing.length > 0) {
    notes.push(
      `details of ${missing.length} advisory record(s) are not cached: ${missing.join(", ")}`,
    );
  }
  if (!kev) notes.push("the CISA KEV catalog is not cached; KEV flags are missing");

  const findings = buildFindings(queryable, ids, vulns, kev);
  const status: ScanStatus =
    queryable.length > 0 && unchecked.length === queryable.length
      ? "skipped"
      : unchecked.length > 0 || missing.length > 0 || !kev
        ? "partial"
        : "complete";
  return {
    status,
    notes,
    components: {
      total: packages.length,
      queried: queryable.length - unchecked.length,
      unchecked: unchecked.length + skipped,
    },
    summary: summarize(findings),
    findings,
    kevCatalog: kev ? { version: kev.catalogVersion, released: kev.dateReleased } : null,
  };
}

/** scan.json: deterministic, no timestamps or feed versions. */
export function scanJson(report: ScanReport): string {
  const { kevCatalog: _omitted, ...rest } = report;
  return `${JSON.stringify(
    {
      // "cra-kit" is the tool id the hosted service validates in scan.json; keep it.
      tool: { name: "cra-kit", version: CLI_VERSION },
      sources: ["https://osv.dev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
      ...rest,
    },
    null,
    2,
  )}\n`;
}

/** One-line result for summaries; a skipped scan never reads as "0 findings". */
export function scanHeadline(report: ScanReport): string {
  if (report.status === "skipped") {
    return "not performed - offline with no cached OSV results; run once without --offline";
  }
  const s = report.summary;
  return `${s.total} finding${s.total === 1 ? "" : "s"}: ${s.kev} known exploited (KEV), ${s.critical} critical, ${s.high} high (${report.status})`;
}
