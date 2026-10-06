import { asArray, asRecord, asString } from "../guards";
import { CACHE_TTL_MS, type FeedCache, type NetOptions, requestJson } from "./net";

export const OSV_API = "https://api.osv.dev";
/** OSV accepts up to 1000 queries per batch; smaller batches keep responses manageable. */
export const OSV_BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const QUERY_INDEX = "osv-queries.json";

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvAffected {
  ecosystem: string | null;
  name: string | null;
  purl: string | null;
  ranges: Array<{ type: string; events: OsvEvent[] }>;
  severity: Array<{ type: string; score: string }>;
}

export interface OsvVuln {
  id: string;
  summary: string;
  aliases: string[];
  withdrawn: boolean;
  severity: Array<{ type: string; score: string }>;
  databaseSeverity: string | null;
  affected: OsvAffected[];
}

function severityList(value: unknown): Array<{ type: string; score: string }> {
  return asArray(value).flatMap((raw) => {
    const s = asRecord(raw);
    const type = asString(s.type);
    const score = asString(s.score);
    return type && score ? [{ type, score }] : [];
  });
}

/** Narrows an OSV record (https://ossf.github.io/osv-schema/) to the fields cra uses. */
export function toOsvVuln(raw: unknown): OsvVuln | null {
  const v = asRecord(raw);
  const id = asString(v.id);
  if (!id) return null;
  const details = asString(v.details) ?? "";
  return {
    id,
    summary: asString(v.summary) ?? details.split(/\r?\n/)[0]?.slice(0, 200) ?? "",
    aliases: asArray(v.aliases).filter((a): a is string => typeof a === "string"),
    withdrawn: asString(v.withdrawn) !== undefined,
    severity: severityList(v.severity),
    databaseSeverity: asString(asRecord(v.database_specific).severity) ?? null,
    affected: asArray(v.affected).map((rawAffected) => {
      const a = asRecord(rawAffected);
      const pkg = asRecord(a.package);
      return {
        ecosystem: asString(pkg.ecosystem) ?? null,
        name: asString(pkg.name) ?? null,
        purl: asString(pkg.purl) ?? null,
        ranges: asArray(a.ranges).map((rawRange) => {
          const r = asRecord(rawRange);
          return {
            type: asString(r.type) ?? "",
            events: asArray(r.events).map((e) => {
              const ev = asRecord(e);
              return {
                introduced: asString(ev.introduced),
                fixed: asString(ev.fixed),
                last_affected: asString(ev.last_affected),
              };
            }),
          };
        }),
        severity: severityList(a.severity),
      };
    }),
  };
}

export interface OsvDeps {
  net: NetOptions;
  cache: FeedCache;
  offline: boolean;
  api: string;
}

type QueryIndex = Record<string, { fetchedAt: string; ids: string[] }>;

/**
 * Vulnerability ids per purl from /v1/querybatch, in batches of
 * OSV_BATCH_SIZE, following next_page_token until every query is exhausted.
 * No caching: the CLI caches around it, the hosted service stores matches.
 */
export async function fetchOsvIds(
  purls: string[],
  net: NetOptions,
  api: string,
): Promise<Map<string, string[]>> {
  const ids = new Map<string, string[]>();
  for (let start = 0; start < purls.length; start += OSV_BATCH_SIZE) {
    const batch = purls.slice(start, start + OSV_BATCH_SIZE);
    const found = new Map<string, Set<string>>(batch.map((p) => [p, new Set<string>()]));
    let pending = batch.map((purl) => ({ purl, pageToken: undefined as string | undefined }));
    while (pending.length > 0) {
      const response = asRecord(
        await requestJson(net, `${api}/v1/querybatch`, {
          queries: pending.map((q) => ({
            package: { purl: q.purl },
            ...(q.pageToken ? { page_token: q.pageToken } : {}),
          })),
        }),
      );
      const results = asArray(response.results);
      const next: typeof pending = [];
      pending.forEach((query, i) => {
        const result = asRecord(results[i]);
        for (const vuln of asArray(result.vulns)) {
          const id = asString(asRecord(vuln).id);
          if (id) found.get(query.purl)?.add(id);
        }
        const token = asString(result.next_page_token);
        if (token) next.push({ purl: query.purl, pageToken: token });
      });
      pending = next;
    }
    for (const [purl, set] of found) ids.set(purl, [...set].sort());
  }
  return ids;
}

/**
 * Vulnerability ids per purl from /v1/querybatch, paginating where OSV
 * returns next_page_token. Results are cached per purl; with --offline only
 * the cache is used and purls never queried before come back unchecked.
 */
export async function queryOsv(
  purls: string[],
  deps: OsvDeps,
): Promise<{ ids: Map<string, string[]>; unchecked: string[] }> {
  const cached = await deps.cache.read(QUERY_INDEX);
  const index: QueryIndex = {};
  for (const [purl, entry] of Object.entries(asRecord(cached?.data))) {
    const e = asRecord(entry);
    const fetchedAt = asString(e.fetchedAt);
    if (fetchedAt) {
      index[purl] = {
        fetchedAt,
        ids: asArray(e.ids).filter((x): x is string => typeof x === "string"),
      };
    }
  }
  const now = deps.cache.now.getTime();
  const isFresh = (purl: string) => {
    const entry = index[purl];
    return entry !== undefined && now - new Date(entry.fetchedAt).getTime() < CACHE_TTL_MS;
  };
  const stale = deps.offline ? [] : purls.filter((p) => !isFresh(p));

  if (stale.length > 0) {
    const fetchedAt = deps.cache.now.toISOString();
    for (const [purl, ids] of await fetchOsvIds(stale, deps.net, deps.api))
      index[purl] = { fetchedAt, ids };
    await deps.cache.write(QUERY_INDEX, index);
  }

  const ids = new Map<string, string[]>();
  const unchecked: string[] = [];
  for (const purl of purls) {
    const entry = index[purl];
    if (entry) ids.set(purl, entry.ids);
    else unchecked.push(purl);
  }
  return { ids, unchecked };
}

const vulnFile = (id: string) => `osv-vulns/${id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;

/** Full OSV records for the given ids (/v1/vulns/{id}), cached per id. */
export async function fetchVulns(
  ids: string[],
  deps: OsvDeps,
): Promise<{ vulns: Map<string, OsvVuln>; missing: string[] }> {
  const vulns = new Map<string, OsvVuln>();
  const missing: string[] = [];
  const queue = [...ids];
  const worker = async () => {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
      const cached = await deps.cache.read(vulnFile(id));
      let vuln = cached ? toOsvVuln(cached.data) : null;
      if ((!cached?.fresh || !vuln) && !deps.offline) {
        const raw = await requestJson(deps.net, `${deps.api}/v1/vulns/${encodeURIComponent(id)}`);
        vuln = toOsvVuln(raw);
        if (vuln) await deps.cache.write(vulnFile(id), raw);
      }
      if (vuln) vulns.set(id, vuln);
      else missing.push(id);
    }
  };
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, ids.length) }, worker));
  return { vulns, missing: missing.sort() };
}
