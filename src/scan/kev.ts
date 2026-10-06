import { asArray, asRecord, asString } from "../guards";
import { type FeedCache, type NetOptions, requestJson } from "./net";

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_FILE = "kev.json";

export interface KevEntry {
  cveID: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

export interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  byCve: Map<string, KevEntry>;
}

/** Keeps the fields cra reports; the full feed is ~1.5 MB. */
export function toKevCatalog(raw: unknown): KevCatalog | null {
  const feed = asRecord(raw);
  const list = asArray(feed.vulnerabilities);
  if (list.length === 0) return null;
  const byCve = new Map<string, KevEntry>();
  for (const item of list) {
    const v = asRecord(item);
    const cveID = asString(v.cveID);
    if (!cveID) continue;
    byCve.set(cveID.toUpperCase(), {
      cveID,
      vulnerabilityName: asString(v.vulnerabilityName) ?? "",
      dateAdded: asString(v.dateAdded) ?? "",
      dueDate: asString(v.dueDate) ?? "",
      knownRansomwareCampaignUse: asString(v.knownRansomwareCampaignUse) ?? "Unknown",
    });
  }
  return {
    catalogVersion: asString(feed.catalogVersion) ?? "",
    dateReleased: asString(feed.dateReleased) ?? "",
    byCve,
  };
}

/**
 * The CISA Known Exploited Vulnerabilities catalog, fresh from the cache when
 * younger than the TTL. Offline runs use any cached copy, or none.
 */
export async function loadKev(deps: {
  net: NetOptions;
  cache: FeedCache;
  offline: boolean;
  url: string;
}): Promise<KevCatalog | null> {
  const cached = await deps.cache.read(KEV_FILE);
  const fromCache = cached ? toKevCatalog(cached.data) : null;
  if (fromCache && (cached?.fresh || deps.offline)) return fromCache;
  if (deps.offline) return null;
  const feed = asRecord(await requestJson(deps.net, deps.url));
  const trimmed = {
    catalogVersion: feed.catalogVersion,
    dateReleased: feed.dateReleased,
    vulnerabilities: asArray(feed.vulnerabilities).map((item) => {
      const v = asRecord(item);
      return {
        cveID: v.cveID,
        vulnerabilityName: v.vulnerabilityName,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
      };
    }),
  };
  const catalog = toKevCatalog(trimmed);
  if (catalog) await deps.cache.write(KEV_FILE, trimmed);
  return catalog;
}
