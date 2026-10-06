import type { FailOn } from "../config";
import { compareStrings } from "../format";
import type { BomPackage } from "../sbom/cyclonedx";
import { normalizePypiName, OSV_ECOSYSTEM, parsePurl } from "../sbom/purl";
import { cvss2BaseScore, cvss3BaseScore, ratingV2, ratingV3, type Severity } from "./cvss";
import type { KevCatalog } from "./kev";
import type { OsvAffected, OsvVuln } from "./osv";

/** Orders version strings with numeric runs compared as numbers (2.3.1 before 2.12.2), locale-independent. */
const compareVersions = new Intl.Collator("en", { numeric: true, sensitivity: "variant" }).compare;

export type SeveritySource = "CVSS_V3" | "CVSS_V2" | "database" | null;

export interface Finding {
  /** Primary advisory id (GHSA-, RUSTSEC-, GO-, PYSEC-...). */
  id: string;
  /** Every other id of the same issue, CVE ids included. */
  aliases: string[];
  summary: string;
  package: { purl: string; name: string; version: string | null; ecosystem: string };
  severity: Severity;
  score: number | null;
  vector: string | null;
  severitySource: SeveritySource;
  kev: {
    cve: string;
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
  } | null;
  fixedVersions: string[];
  url: string;
}

export interface Summary {
  total: number;
  kev: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  none: 1,
  unknown: 0,
};

const DATABASE_SEVERITY: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
};

/** Severity from CVSS v3 when present, else the database's rating, else CVSS v2. */
export function severityOf(vuln: OsvVuln): {
  severity: Severity;
  score: number | null;
  vector: string | null;
  source: SeveritySource;
} {
  const entries = [...vuln.severity, ...vuln.affected.flatMap((a) => a.severity)];
  let best: { score: number; vector: string } | null = null;
  for (const s of entries) {
    if (s.type !== "CVSS_V3") continue;
    const score = cvss3BaseScore(s.score);
    if (score !== null && (!best || score > best.score)) best = { score, vector: s.score };
  }
  if (best) return { severity: ratingV3(best.score), ...best, source: "CVSS_V3" };
  const database = DATABASE_SEVERITY[(vuln.databaseSeverity ?? "").toUpperCase()];
  if (database) {
    const vector = entries.find((s) => s.type.startsWith("CVSS"))?.score ?? null;
    return { severity: database, score: null, vector, source: "database" };
  }
  for (const s of entries) {
    if (s.type !== "CVSS_V2") continue;
    const score = cvss2BaseScore(s.score);
    if (score !== null && (!best || score > best.score)) best = { score, vector: s.score };
  }
  if (best) return { severity: ratingV2(best.score), ...best, source: "CVSS_V2" };
  return {
    severity: "unknown",
    score: null,
    vector: entries[0]?.score ?? null,
    source: null,
  };
}

function matchesPackage(affected: OsvAffected, pkg: BomPackage): boolean {
  if (affected.purl) {
    const parsed = parsePurl(affected.purl);
    if (parsed && parsed.type === pkg.type && parsed.name === pkg.name) return true;
  }
  if (affected.ecosystem !== OSV_ECOSYSTEM[pkg.type] || affected.name === null) return false;
  return pkg.type === "pypi"
    ? normalizePypiName(affected.name) === normalizePypiName(pkg.name)
    : affected.name === pkg.name;
}

/** Versions that fix the vulnerability for this package (SEMVER/ECOSYSTEM ranges). */
export function fixedVersions(vuln: OsvVuln, pkg: BomPackage): string[] {
  const fixed = new Set<string>();
  for (const affected of vuln.affected) {
    if (!matchesPackage(affected, pkg)) continue;
    for (const range of affected.ranges) {
      if (range.type === "GIT") continue;
      for (const event of range.events) if (event.fixed) fixed.add(event.fixed);
    }
  }
  return [...fixed].sort(compareVersions);
}

const PRIMARY_PREFERENCE = ["GHSA-", "RUSTSEC-", "GO-", "PYSEC-"];
const primaryRank = (id: string) => {
  const index = PRIMARY_PREFERENCE.findIndex((p) => id.startsWith(p));
  return index < 0
    ? id.startsWith("CVE-")
      ? PRIMARY_PREFERENCE.length + 1
      : PRIMARY_PREFERENCE.length
    : index;
};

/**
 * One finding per package and issue: OSV often returns the same issue under
 * several ids (GHSA and PYSEC, say), linked through aliases, so ids sharing
 * an alias are merged. Each finding is cross-referenced with CISA KEV through
 * its CVE ids.
 */
export function buildFindings(
  packages: BomPackage[],
  idsByPurl: Map<string, string[]>,
  vulns: Map<string, OsvVuln>,
  kev: KevCatalog | null,
): Finding[] {
  const findings: Finding[] = [];
  for (const pkg of packages) {
    const records = (idsByPurl.get(pkg.purl) ?? [])
      .map((id) => vulns.get(id))
      .filter((v): v is OsvVuln => v !== undefined && !v.withdrawn);
    // Union-find over ids and aliases.
    const parent = new Map<string, string>();
    const find = (x: string): string => {
      const p = parent.get(x) ?? x;
      if (p === x) return x;
      const root = find(p);
      parent.set(x, root);
      return root;
    };
    const union = (a: string, b: string) => {
      const ra = find(a);
      const rb = find(b);
      if (ra !== rb) parent.set(ra, rb);
    };
    for (const v of records) for (const alias of v.aliases) union(v.id, alias);
    const groups = new Map<string, OsvVuln[]>();
    for (const v of records) {
      const root = find(v.id);
      groups.set(root, [...(groups.get(root) ?? []), v]);
    }

    for (const group of groups.values()) {
      const ordered = [...group].sort(
        (a, b) => primaryRank(a.id) - primaryRank(b.id) || compareStrings(a.id, b.id),
      );
      const primary = ordered[0];
      if (!primary) continue;
      const ids = new Set(ordered.flatMap((v) => [v.id, ...v.aliases]));
      ids.delete(primary.id);
      const severities = ordered.map(severityOf);
      const best = severities.reduce((a, b) =>
        SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ||
        (SEVERITY_RANK[b.severity] === SEVERITY_RANK[a.severity] &&
          (b.score ?? -1) > (a.score ?? -1))
          ? b
          : a,
      );
      const cves = [primary.id, ...ids].filter((id) => id.startsWith("CVE-")).sort(compareStrings);
      const kevHit = cves
        .map((cve) => kev?.byCve.get(cve.toUpperCase()))
        .find((e) => e !== undefined);
      findings.push({
        id: primary.id,
        aliases: [...ids].sort(compareStrings),
        summary: ordered.find((v) => v.summary)?.summary ?? "",
        package: {
          purl: pkg.purl,
          name: pkg.name,
          version: pkg.version,
          ecosystem: OSV_ECOSYSTEM[pkg.type] ?? pkg.type,
        },
        severity: best.severity,
        score: best.score,
        vector: best.vector,
        severitySource: best.source,
        kev: kevHit
          ? {
              cve: kevHit.cveID,
              dateAdded: kevHit.dateAdded,
              dueDate: kevHit.dueDate,
              knownRansomwareCampaignUse: kevHit.knownRansomwareCampaignUse,
            }
          : null,
        fixedVersions: [...new Set(ordered.flatMap((v) => fixedVersions(v, pkg)))].sort(
          compareVersions,
        ),
        url: `https://osv.dev/vulnerability/${primary.id}`,
      });
    }
  }
  return findings.sort(
    (a, b) =>
      Number(b.kev !== null) - Number(a.kev !== null) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (b.score ?? -1) - (a.score ?? -1) ||
      compareStrings(a.package.purl, b.package.purl) ||
      compareStrings(a.id, b.id),
  );
}

export function summarize(findings: Finding[]): Summary {
  const summary: Summary = {
    total: findings.length,
    kev: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const f of findings) {
    if (f.kev) summary.kev++;
    if (f.severity === "critical") summary.critical++;
    else if (f.severity === "high") summary.high++;
    else if (f.severity === "medium") summary.medium++;
    else if (f.severity === "low") summary.low++;
    else summary.unknown++;
  }
  return summary;
}

/**
 * Exit policy for scan.failOn. A finding listed in CISA KEV is actively
 * exploited and counts at every threshold except "none".
 */
export function exceedsThreshold(findings: Finding[], failOn: FailOn): boolean {
  if (failOn === "none") return false;
  const minimum = failOn === "high" ? SEVERITY_RANK.high : SEVERITY_RANK.critical;
  return findings.some(
    (f) => f.kev !== null || (failOn !== "kev" && SEVERITY_RANK[f.severity] >= minimum),
  );
}
