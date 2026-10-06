import { humanize, isoDate, mdTable, monthYear, plural } from "../format";
import {
  type DocsInput,
  findingsTable,
  header,
  keyValueTable,
  sbomSummary,
  scanSummary,
  scopeRows,
  supportFacts,
  TODO,
  type VendorBlocks,
} from "./common";

export function technicalDocumentation(input: DocsInput, v: VendorBlocks): string {
  const { product } = input;
  const support = supportFacts(input);
  const hardware = product.distribution === "firmware_or_device";
  const supportCheck =
    support.problems.length === 0
      ? `Meets the minimum of Art. 13(8) measured from ${support.placedIsEstimate ? "this release" : "first placing on the market"} (${isoDate(support.placed)}).`
      : support.problems.includes("ends_before_placed")
        ? "The support period ends before the product is placed on the market: correct `supportEndsAt`."
        : "Shorter than five years without a declared shorter expected use time (Art. 13(8)): extend it, or set `expectedUseYears` and justify it below.";

  return [
    header(
      `EU technical documentation - ${product.name} ${input.version}`,
      input,
      "Structure of Annex VII; drawn up before placing on the market and kept up to date during the support period (Art. 31(2)).",
    ),
    "",
    keyValueTable([
      ["Product", product.name],
      ["Version covered", input.version],
      ["Release date", isoDate(input.releaseDate)],
      ["Manufacturer", `${product.manufacturer.name}, ${product.manufacturer.address}`],
      ["Distribution", humanize(product.distribution)],
      ["Core function (Annex III/IV check)", humanize(product.coreFunction)],
      ...scopeRows(input),
      [
        "Keep this documentation until at least",
        `${isoDate(support.retainedUntil)} (10 years after placing on the market or the support period, whichever is longer; Art. 13(13))`,
      ],
    ]),
    "",
    "## 1. General description (Annex VII, point 1)",
    "",
    "### 1(a) Intended purpose",
    "",
    product.intendedPurpose,
    "",
    v.block(
      "intended-purpose-details",
      `${TODO}: add the conditions of use, the intended users and the operational environment, and any remote data processing the product relies on (Art. 3(2)).`,
    ),
    "",
    "### 1(b) Versions of software affecting compliance",
    "",
    `This file documents version ${input.version}. Earlier versions are documented in the git history of this directory.`,
    "",
    v.block(
      "versions",
      `${TODO}: list the versions still supported and how users of older versions reach the latest one free of charge (Art. 13(10)).`,
    ),
    "",
    "### 1(c) Photographs or illustrations (hardware products)",
    "",
    hardware
      ? v.block(
          "hardware-illustrations",
          `${TODO}: add photographs or illustrations showing external features, marking and internal layout.`,
        )
      : "Not applicable: the product is software.",
    "",
    "### 1(d) User information and instructions",
    "",
    "See [user-information.md](user-information.md) (Annex II).",
    "",
    "## 2. Design, development, production and vulnerability handling (Annex VII, point 2)",
    "",
    "### 2(a) Design, development and system architecture",
    "",
    v.block(
      "architecture",
      `${TODO}: describe the system architecture - how the software components build on or feed into each other and integrate into the overall processing - with drawings or diagrams where useful.`,
    ),
    "",
    "### 2(b) Vulnerability handling processes",
    "",
    `- Software bill of materials: [sbom.cdx.json](sbom.cdx.json), ${input.sbom.packages.length} components, regenerated on every release.`,
    "- Coordinated vulnerability disclosure policy: [vulnerability-handling.md](vulnerability-handling.md).",
    `- Contact address for reporting vulnerabilities: ${product.securityContact.email}${product.securityContact.url ? `, ${product.securityContact.url}` : ""}, published in [security.txt](security.txt).`,
    "- Reporting of actively exploited vulnerabilities and severe incidents: [reporting-runbook.md](reporting-runbook.md).",
    "",
    v.block(
      "update-distribution",
      `${TODO}: describe the technical solution for the secure distribution of updates (channel, signing, integrity checks, automatic updates per Annex I Part I(2)(c)).`,
    ),
    "",
    "### 2(c) Production and monitoring processes",
    "",
    "Each release regenerates these records with cra (ReleaseKeep); the git history of this directory records what changed between releases.",
    "",
    v.block(
      "production-monitoring",
      `${TODO}: describe the build and release pipeline, how its integrity is protected, how the product and its components are monitored after release, and how these processes are validated.`,
    ),
    "",
    "## 3. Cybersecurity risk assessment (Annex VII, point 3)",
    "",
    "See [risk-assessment.md](risk-assessment.md) (Art. 13(2)-(4)).",
    "",
    "## 4. Support period (Annex VII, point 4)",
    "",
    `Support ends in ${monthYear(product.supportEndsAt)} (${isoDate(product.supportEndsAt)}). ${supportCheck} See [support-period.md](support-period.md).`,
    "",
    v.block(
      "support-period-rationale",
      `${TODO}: record what was taken into account to set the support period (Art. 13(8)): expected time in use, reasonable user expectations, the nature and intended purpose of the product, support periods of similar products and of core third-party components, availability of the operating environment.`,
    ),
    "",
    "## 5. Harmonised standards, common specifications and certification (Annex VII, point 5)",
    "",
    v.block(
      "standards",
      `${TODO}: list the harmonised standards, common specifications (Art. 27) or European cybersecurity certification schemes applied in full or in part, naming the parts applied. Where none are applied, describe the solutions adopted to meet Annex I Parts I and II and other technical specifications used.`,
    ),
    "",
    "## 6. Test reports (Annex VII, point 6)",
    "",
    "### Automated vulnerability scan of this release",
    "",
    scanSummary(input),
    "",
    findingsTable(input, 25),
    "",
    v.block(
      "test-reports",
      `${TODO}: link the reports of other tests verifying conformity with Annex I Parts I and II (security tests, code review, penetration tests, fuzzing) and their dates.`,
    ),
    "",
    "## 7. EU declaration of conformity (Annex VII, point 7)",
    "",
    "See [declaration-of-conformity.md](declaration-of-conformity.md) (Annex V).",
    "",
    "## 8. Software bill of materials (Annex VII, point 8)",
    "",
    "Provided to a market surveillance authority on reasoned request.",
    "",
    sbomSummary(input),
    "",
    input.sbom.direct.length > 0
      ? mdTable(
          ["Direct dependency", "Version", "Package URL"],
          input.sbom.direct.map((p) => [p.name, p.version ?? "-", `\`${p.purl}\``]),
        )
      : "No direct third-party dependencies were found.",
    "",
  ].join("\n");
}

/** Annex I Part I(2): requirement letter, short title, full text. */
export const ANNEX_I_PART_I: ReadonlyArray<{ key: string; title: string; text: string }> = [
  {
    key: "a",
    title: "No known exploitable vulnerabilities",
    text: "be made available on the market without known exploitable vulnerabilities",
  },
  {
    key: "b",
    title: "Secure by default configuration",
    text: "be made available on the market with a secure by default configuration, unless otherwise agreed between manufacturer and business user in relation to a tailor-made product, including the possibility to reset the product to its original state",
  },
  {
    key: "c",
    title: "Security updates",
    text: "ensure that vulnerabilities can be addressed through security updates, including, where applicable, through automatic security updates that are installed within an appropriate timeframe enabled as a default setting, with a clear and easy-to-use opt-out mechanism, through the notification of available updates to users, and the option to temporarily postpone them",
  },
  {
    key: "d",
    title: "Protection from unauthorised access",
    text: "ensure protection from unauthorised access by appropriate control mechanisms, including but not limited to authentication, identity or access management systems, and report on possible unauthorised access",
  },
  {
    key: "e",
    title: "Confidentiality of data",
    text: "protect the confidentiality of stored, transmitted or otherwise processed data, personal or other, such as by encrypting relevant data at rest or in transit by state of the art mechanisms, and by using other technical means",
  },
  {
    key: "f",
    title: "Integrity of data, commands, programs and configuration",
    text: "protect the integrity of stored, transmitted or otherwise processed data, personal or other, commands, programs and configuration against any manipulation or modification not authorised by the user, and report on corruptions",
  },
  {
    key: "g",
    title: "Data minimisation",
    text: "process only data, personal or other, that are adequate, relevant and limited to what is necessary in relation to the intended purpose of the product (data minimisation)",
  },
  {
    key: "h",
    title: "Availability of essential functions",
    text: "protect the availability of essential and basic functions, also after an incident, including through resilience and mitigation measures against denial-of-service attacks",
  },
  {
    key: "i",
    title: "Minimise impact on other devices and networks",
    text: "minimise the negative impact by the products themselves or connected devices on the availability of services provided by other devices or networks",
  },
  {
    key: "j",
    title: "Limited attack surface",
    text: "be designed, developed and produced to limit attack surfaces, including external interfaces",
  },
  {
    key: "k",
    title: "Exploitation mitigation",
    text: "be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques",
  },
  {
    key: "l",
    title: "Security logging and monitoring",
    text: "provide security related information by recording and monitoring relevant internal activity, including the access to or modification of data, services or functions, with an opt-out mechanism for the user",
  },
  {
    key: "m",
    title: "Secure data removal and transfer",
    text: "provide the possibility for users to securely and easily remove on a permanent basis all data and settings and, where such data can be transferred to other products or systems, ensure that this is done in a secure manner",
  },
];

const ASSESSMENT_TEMPLATE = [
  `${TODO}: fill in the four lines below, then delete this line.`,
  "- Applicable: yes / no (if no, give the justification Art. 13(4) requires)",
  "- Status: implemented / partially implemented / planned / not applicable",
  "- How it is met, informed by the risk analysis:",
  "- Evidence (tests, configuration, design records):",
].join("\n");

/** "- Applicable: ..." or "- Status: ..." of a completed vendor block, for the overview table. */
function fieldOf(body: string, field: string): string {
  if (body.includes(TODO)) return "not assessed";
  return new RegExp(`^- ${field}:[ \\t]*(.*)$`, "m").exec(body)?.[1]?.trim() || "not stated";
}

export function riskAssessment(input: DocsInput, v: VendorBlocks): string {
  const { product, scan } = input;
  const evidence: Record<string, string> = {
    a: scan
      ? `Automated evidence: the ${scan.status} OSV and CISA KEV scan of this release found ${plural(scan.summary.total, "known vulnerability", "known vulnerabilities")} in third-party components, ${scan.summary.kev} of them listed as known exploited. Whether each is exploitable in this product is your assessment.`
      : `Automated evidence: none - the vulnerability scan did not run (${input.scanError ?? "unknown error"}).`,
    c: `Automated evidence: security updates are owed until ${monthYear(product.supportEndsAt)} (support period, Art. 13(8)); each stays available per Art. 13(9), see [support-period.md](support-period.md).`,
  };
  const overview = ANNEX_I_PART_I.map((r) => {
    const body = v.body(`annex-i-2${r.key}`, ASSESSMENT_TEMPLATE);
    return [`(2)(${r.key}) ${r.title}`, fieldOf(body, "Applicable"), fieldOf(body, "Status")];
  });

  return [
    header(
      `Cybersecurity risk assessment - ${product.name} ${input.version}`,
      input,
      "Structure of Art. 13(2)-(4): an analysis of cybersecurity risks based on the intended purpose, reasonably foreseeable use and conditions of use, stating for each requirement of Annex I Part I(2) whether and how it applies.",
    ),
    "",
    "## 1. Context of use (Art. 13(3))",
    "",
    `**Intended purpose (from cra.yml):** ${product.intendedPurpose}`,
    "",
    `**Distribution:** ${humanize(product.distribution)}. **Support period ends:** ${monthYear(product.supportEndsAt)}${product.expectedUseYears !== null ? `. **Expected use time:** ${product.expectedUseYears} years` : ""}.`,
    "",
    "### Reasonably foreseeable use and misuse",
    "",
    v.block(
      "foreseeable-use",
      `${TODO}: uses beyond the intended purpose that are likely in practice (Art. 3(24)).`,
    ),
    "",
    "### Operational environment and assets to protect",
    "",
    v.block(
      "environment-assets",
      `${TODO}: where the product runs, what it connects to, and the assets at stake (data, functions, users' systems).`,
    ),
    "",
    "### Threats and risk method",
    "",
    v.block(
      "threats",
      `${TODO}: the threat sources and scenarios considered, and how likelihood and impact were rated (method, scale, acceptance criteria).`,
    ),
    "",
    "## 2. Overview",
    "",
    "Built from the assessments below on every regeneration.",
    "",
    mdTable(["Annex I Part I requirement", "Applicable", "Status"], overview),
    "",
    "## 3. Appropriate level of cybersecurity (Annex I Part I(1))",
    "",
    v.block(
      "annex-i-1",
      `${TODO}: how the overall level of security was matched to the risks identified above.`,
    ),
    "",
    "## 4. Requirements of Annex I Part I(2)",
    "",
    ...ANNEX_I_PART_I.flatMap((r) => [
      `### (2)(${r.key}) ${r.title}`,
      "",
      `> The product shall ${r.text}.`,
      "",
      ...(evidence[r.key] ? [evidence[r.key] ?? "", ""] : []),
      v.block(`annex-i-2${r.key}`, ASSESSMENT_TEMPLATE),
      "",
    ]),
    "## 5. Vulnerability handling (Annex I Part II)",
    "",
    "How each requirement of Annex I Part II is met is recorded in [vulnerability-handling.md](vulnerability-handling.md).",
    "",
    "## 6. Third-party components (Art. 13(5)-(6))",
    "",
    `The SBOM lists ${input.sbom.packages.length} third-party components (${input.sbom.direct.length} direct). ${scan ? `The scan of this release found ${plural(scan.summary.total, "known vulnerability", "known vulnerabilities")} in them.` : ""}`.trim(),
    "",
    v.block(
      "due-diligence",
      `${TODO}: how components are selected and kept current (maintenance activity, security update history, known vulnerabilities, CE marking where applicable), and how vulnerabilities found in components are reported to their maintainers (Art. 13(6)).`,
    ),
    "",
    "## 7. Review history (Art. 13(3), 13(7))",
    "",
    v.block(
      "review-history",
      `${TODO}: date, reviewer and outcome of each review of this assessment. Review at least on every substantial change and when new vulnerabilities or incidents change the risk picture.`,
    ),
    "",
  ].join("\n");
}
