import { humanize, isoDate, mdTable, monthYear } from "../format";
import { addYears, MIN_SUPPORT_YEARS, updateAvailableUntil } from "../rules";
import { type DocsInput, header, supportFacts, TODO, type VendorBlocks } from "./common";

export function supportPeriod(input: DocsInput, v: VendorBlocks): string {
  const { product } = input;
  const ends = product.supportEndsAt;
  const support = supportFacts(input);
  const minimumYears =
    product.expectedUseYears !== null && product.expectedUseYears < MIN_SUPPORT_YEARS
      ? product.expectedUseYears
      : MIN_SUPPORT_YEARS;
  const crossover = addYears(ends, -10);
  const rows: Array<[string, string, string]> = [
    [
      `This release (${input.version})`,
      isoDate(input.releaseDate),
      isoDate(updateAvailableUntil(input.releaseDate, ends)),
    ],
    ["Last day of support", isoDate(ends), isoDate(updateAvailableUntil(ends, ends))],
  ];
  const check =
    support.problems.length === 0
      ? `**Check: passes.** ${monthYear(ends)} is at least ${minimumYears} years after ${support.placedIsEstimate ? "this release (no `placedOnMarketAt` in cra.yml yet)" : `first placing on the market on ${isoDate(support.placed)}`}.`
      : support.problems.includes("ends_before_placed")
        ? "**Check: fails.** The support period ends before the product is placed on the market."
        : `**Check: fails.** The support period is shorter than ${MIN_SUPPORT_YEARS} years from ${isoDate(support.placed)} and no shorter expected use time is declared (\`expectedUseYears\`).`;

  return [
    header(
      `Support period - ${product.name}`,
      input,
      "Support period under Art. 13(8), its end date as stated to buyers (Art. 13(19)) and the availability of security updates (Art. 13(9)).",
    ),
    "",
    "## Statement for the point of sale (Art. 13(19))",
    "",
    `> Security updates for ${product.name} are provided until the end of **${monthYear(ends)}**.`,
    "",
    "State this, at least as month and year, clearly at the time of purchase, and where applicable on the product, its packaging or by digital means.",
    "",
    "## How the period was set (Art. 13(8))",
    "",
    `- End of support: ${isoDate(ends)}.`,
    `- Minimum: ${MIN_SUPPORT_YEARS} years, or the expected use time when the product is expected to be in use for less${product.expectedUseYears !== null ? ` (declared: ${product.expectedUseYears} years)` : ""}.`,
    `- ${check}`,
    "",
    v.block(
      "rationale",
      `${TODO}: why this period reflects how long the product is expected to be in use (user expectations, nature and purpose of the product, support periods of similar products and of core components, availability of the operating environment). This also goes into the technical documentation (Annex VII, point 4).`,
    ),
    "",
    "## Availability of each security update (Art. 13(9))",
    "",
    "Each security update made available during the support period remains available for at least 10 years after it was issued, or for the remainder of the support period, whichever is longer.",
    "",
    mdTable(["Update", "Issued", "Must remain available until"], rows),
    "",
    crossover.getTime() > input.releaseDate.getTime()
      ? `Updates issued before ${isoDate(crossover)} must stay available until the end of support; later ones for 10 years from their issue date, beyond the end of support.`
      : "Every update issued from this release on must stay available for 10 years from its issue date, which reaches beyond the end of support.",
    "",
    v.block(
      "update-archive",
      `${TODO}: where past updates are kept available for download, and how users of a public archive of historical versions are told about the risks of unsupported software (Art. 13(11)).`,
    ),
    "",
    "## Keeping the records (Art. 13(13), 13(18))",
    "",
    `Keep the technical documentation, the EU declaration of conformity and the user information available until at least ${isoDate(support.retainedUntil)}: 10 years after placing on the market or the support period, whichever is longer${support.placedIsEstimate ? " (computed from this release until `placedOnMarketAt` is set)" : ""}.`,
    "",
    "## End of support (Art. 13(19), second subparagraph)",
    "",
    v.block(
      "end-of-support-notice",
      `${TODO}: how users are notified that the product reached the end of its support period, where technically feasible.`,
    ),
    "",
  ].join("\n");
}

export function userInformation(input: DocsInput, v: VendorBlocks): string {
  const { product } = input;
  const m = product.manufacturer;
  const contact = product.securityContact;
  const item = (n: string, requirement: string, known: string | null, id: string, todo: string) => [
    `### ${n}`,
    "",
    `> ${requirement}`,
    "",
    ...(known ? [known, ""] : []),
    v.block(id, todo),
    "",
  ];
  return [
    header(
      `Information and instructions to the user - ${product.name}`,
      input,
      "Checklist of the information Annex II requires to accompany the product (Art. 13(18)), pre-filled where cra.yml already knows the answer.",
    ),
    "",
    `Provide it in paper or electronic form, in a language users and market surveillance authorities easily understand (cra.yml: ${product.languages.join(", ")}), and keep it available for at least 10 years after placing on the market or for the support period, whichever is longer (Art. 13(18)).`,
    "",
    ...item(
      "1. Manufacturer",
      "Name, registered trade name or trademark, postal address, email or other digital contact and, where available, the website.",
      `${m.name}, ${m.address}, ${m.email}${m.website ? `, ${m.website}` : ""}`,
      "item-1",
      `- Where users find this: ${TODO}`,
    ),
    ...item(
      "2. Single point of contact for vulnerabilities",
      "Where information about vulnerabilities can be reported and received, and where the coordinated vulnerability disclosure policy can be found.",
      `${contact.email}${contact.url ? `; policy: ${contact.url}` : "; policy: vulnerability-handling.md (publish it and set `securityContact.url`)"}`,
      "item-2",
      `- Where users find this: ${TODO}`,
    ),
    ...item(
      "3. Product identification",
      "Name and type and any additional information enabling the unique identification of the product.",
      `${product.name}, ${humanize(product.distribution)}, version ${input.version}`,
      "item-3",
      `- How users find the version they run: ${TODO}`,
    ),
    ...item(
      "4. Intended purpose and security properties",
      "The intended purpose, including the security environment provided by the manufacturer, the essential functionalities and information about the security properties.",
      product.intendedPurpose,
      "item-4",
      `- Security environment, essential functionalities and security properties: ${TODO}`,
    ),
    ...item(
      "5. Circumstances that may lead to significant cybersecurity risks",
      "Any known or foreseeable circumstance, related to use in accordance with the intended purpose or under conditions of reasonably foreseeable misuse, which may lead to significant cybersecurity risks.",
      null,
      "item-5",
      `${TODO}: list them (see the risk assessment, section 1).`,
    ),
    ...item(
      "6. EU declaration of conformity",
      "Where applicable, the internet address at which the EU declaration of conformity can be accessed.",
      null,
      "item-6",
      `- URL of the declaration: ${TODO}`,
    ),
    ...item(
      "7. Technical security support and end of support",
      "The type of technical security support offered and the end date of the support period during which users can expect vulnerabilities to be handled and to receive security updates.",
      `Security updates until the end of ${monthYear(product.supportEndsAt)}.`,
      "item-7",
      `- Type of security support offered: ${TODO}`,
    ),
    "### 8. Detailed instructions",
    "",
    "> Detailed instructions, or an internet address referring to them, on:",
    "",
    ...item(
      "8(a) Secure commissioning and use",
      "The necessary measures during initial commissioning and throughout the lifetime of the product to ensure its secure use.",
      null,
      "item-8a",
      `${TODO}`,
    ),
    ...item(
      "8(b) Effect of changes on data security",
      "How changes to the product can affect the security of data.",
      null,
      "item-8b",
      `${TODO}`,
    ),
    ...item(
      "8(c) Installing security updates",
      "How security-relevant updates can be installed.",
      null,
      "item-8c",
      `${TODO}`,
    ),
    ...item(
      "8(d) Secure decommissioning",
      "The secure decommissioning of the product, including how user data can be securely removed.",
      null,
      "item-8d",
      `${TODO}`,
    ),
    ...item(
      "8(e) Turning off automatic security updates",
      "How the default setting enabling the automatic installation of security updates (Annex I Part I(2)(c)) can be turned off.",
      null,
      "item-8e",
      `${TODO} (or "not applicable" with the reason)`,
    ),
    ...item(
      "8(f) Information for integrators",
      "Where the product is intended for integration into other products, the information the integrator needs to comply with Annex I and Annex VII.",
      product.distribution === "library_or_package" ||
        product.distribution === "plugin_or_extension"
        ? "Applies: the product is distributed for integration into other products."
        : null,
      "item-8f",
      `${TODO} (or "not applicable")`,
    ),
    ...item(
      "9. Software bill of materials",
      "If the manufacturer makes the SBOM available to users, where it can be accessed.",
      `The SBOM of this version is sbom.cdx.json (SHA-256 \`${input.sbom.sha256}\`).`,
      "item-9",
      `- Published to users: ${TODO} yes, at <URL> / no`,
    ),
  ].join("\n");
}
