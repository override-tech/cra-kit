import { asArray, asRecord, asString } from "../src/guards";
import type { FetchLike } from "../src/scan/net";

/** A complete cra.yml for a paid self-hosted product. */
export const VALID = `product:
  name: Acme Backup
  manufacturer:
    name: Acme Software sp. z o.o.
    address: ul. Prosta 1, 00-001 Warszawa, Poland
    email: legal@acme.example
    website: https://acme.example
  distribution: self_hosted_server
  coreFunction: none_of_the_above
  monetisation: [subscription_or_licence]
  isFoss: false
  intendedPurpose: Encrypted backups of company file servers, run on customer premises.
  supportEndsAt: 2032-12
  securityContact:
    email: security@acme.example
    url: https://acme.example/security
    pgpKey: "ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234"
  languages: [en, pl]
`;

export interface MockRequest {
  method: string;
  url: string;
  body: unknown;
}

/**
 * A fetch that answers from `routes` (first matching URL fragment wins) and
 * records every request. Routes may be functions of the parsed request body.
 */
export function mockFetch(
  routes: Array<[string, unknown | ((body: unknown) => unknown)]>,
): FetchLike & { requests: MockRequest[] } {
  const requests: MockRequest[] = [];
  const fetch = async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    requests.push({ method: init?.method ?? "GET", url, body });
    const route = routes.find(([fragment]) => url.includes(fragment));
    if (!route) return new Response("not found", { status: 404 });
    const payload = typeof route[1] === "function" ? route[1](body) : route[1];
    return new Response(JSON.stringify(payload), { status: 200 });
  };
  return Object.assign(fetch, { requests });
}

export const failingFetch: FetchLike = async () => {
  throw new TypeError("fetch failed: getaddrinfo ENOTFOUND api.osv.dev");
};

/** OSV and KEV responses for lodash@4.17.20 and requests@2.19.0. */
export const OSV_VULNS: Record<string, unknown> = {
  "GHSA-35jh-r3h4-6jhm": {
    id: "GHSA-35jh-r3h4-6jhm",
    summary: "Command Injection in lodash",
    aliases: ["CVE-2021-23337"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
    affected: [
      {
        package: { ecosystem: "npm", name: "lodash", purl: "pkg:npm/lodash" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
    database_specific: { severity: "HIGH" },
  },
  "GHSA-29mw-wpgm-hmr9": {
    id: "GHSA-29mw-wpgm-hmr9",
    summary: "Regular Expression Denial of Service (ReDoS) in lodash",
    aliases: ["CVE-2020-28500"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" }],
    affected: [
      {
        package: { ecosystem: "npm", name: "lodash" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] }],
      },
    ],
  },
  "GHSA-x84v-xcm2-53pg": {
    id: "GHSA-x84v-xcm2-53pg",
    summary: "Insufficiently Protected Credentials in Requests",
    aliases: ["CVE-2018-18074"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
    affected: [
      {
        package: { ecosystem: "PyPI", name: "requests" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }],
      },
    ],
  },
  "PYSEC-2018-28": {
    id: "PYSEC-2018-28",
    details:
      "The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI.",
    aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
    affected: [
      {
        package: { ecosystem: "PyPI", name: "Requests" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }],
      },
    ],
  },
  "GHSA-withdrawn-0000": {
    id: "GHSA-withdrawn-0000",
    summary: "Withdrawn advisory",
    withdrawn: "2024-01-01T00:00:00Z",
    affected: [],
  },
};

export const KEV_FEED = {
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  catalogVersion: "2026.10.01",
  dateReleased: "2026-10-01T15:00:00.0000Z",
  count: 2,
  vulnerabilities: [
    {
      cveID: "CVE-2021-23337",
      vendorProject: "Lodash",
      product: "Lodash",
      vulnerabilityName: "Lodash Command Injection (test fixture)",
      dateAdded: "2026-09-30",
      shortDescription: "Test entry.",
      requiredAction: "Apply updates.",
      dueDate: "2026-10-21",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
    {
      cveID: "CVE-2000-0001",
      vulnerabilityName: "Unrelated",
      dateAdded: "2020-01-01",
      dueDate: "2020-01-21",
      knownRansomwareCampaignUse: "Known",
    },
  ],
};

/**
 * OSV routes: querybatch answers per purl (lodash paginates once), vuln
 * details by id; plus the KEV feed.
 */
export function osvRoutes(
  kev: unknown = KEV_FEED,
): Array<[string, unknown | ((body: unknown) => unknown)]> {
  const byPurl: Record<string, string[]> = {
    "pkg:pypi/requests@2.19.0": ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28", "GHSA-withdrawn-0000"],
  };
  return [
    [
      "/v1/querybatch",
      (body: unknown) => ({
        results: asArray(asRecord(body).queries).map((raw) => {
          const query = asRecord(raw);
          const purl = asString(asRecord(query.package).purl) ?? "";
          if (purl === "pkg:npm/lodash@4.17.20") {
            return query.page_token === "page-2"
              ? { vulns: [{ id: "GHSA-29mw-wpgm-hmr9", modified: "2024-01-01T00:00:00Z" }] }
              : { vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }], next_page_token: "page-2" };
          }
          const ids = byPurl[purl];
          return ids ? { vulns: ids.map((id) => ({ id })) } : {};
        }),
      }),
    ],
    ...Object.entries(OSV_VULNS).map(([id, vuln]): [string, unknown] => [`/v1/vulns/${id}`, vuln]),
    ["known_exploited_vulnerabilities.json", kev],
  ];
}
