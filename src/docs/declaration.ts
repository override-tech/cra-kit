import { humanize } from "../format";
import { ROUTE_LABELS, routeArticle } from "../labels";
import { type DocsInput, header, TODO, type VendorBlocks } from "./common";

/** Annex V content, as a draft the manufacturer completes and signs. */
export function declarationOfConformity(input: DocsInput, v: VendorBlocks): string {
  const { product, scope } = input;
  const route = scope.route;
  const notifiedBodyDefault =
    route === "module_a_self_assessment"
      ? "Not applicable: internal control (module A), no notified body involved."
      : route === "module_a_if_standards_applied_else_third_party"
        ? `${TODO}: not applicable if harmonised standards, common specifications or a certification scheme were applied in full and module A was used; otherwise the name and number of the notified body, the procedure (module B+C or H) and the certificate identification.`
        : `${TODO}: name and number of the notified body, description of the conformity assessment procedure performed and identification of the certificate issued.`;

  return [
    header(
      `EU declaration of conformity (draft) - ${product.name} ${input.version}`,
      input,
      "Content of Annex V (Art. 28).",
    ),
    "",
    "> **Draft. This declaration has no legal effect until the manufacturer has completed the conformity assessment procedure (Art. 32), checked every entry below and signed it.** By drawing it up the manufacturer assumes responsibility for the compliance of the product (Art. 28(4)). cra-kit does not declare conformity on anyone's behalf.",
    "",
    `Make the signed declaration available in the languages required by the Member States where the product is made available (Art. 28(2)); cra.yml lists: ${product.languages.join(", ")}.`,
    "",
    "## 1. Product with digital elements",
    "",
    `- Name: ${product.name}`,
    `- Type: ${humanize(product.distribution)}`,
    `- Version: ${input.version}`,
    `- SBOM of this version: sbom.cdx.json, SHA-256 \`${input.sbom.sha256}\``,
    "",
    v.block(
      "product-identification",
      `- Additional identification: ${TODO} (build identifier, editions, etc.)`,
    ),
    "",
    "## 2. Manufacturer",
    "",
    `- Name: ${product.manufacturer.name}`,
    `- Address: ${product.manufacturer.address}`,
    "",
    v.block(
      "authorised-representative",
      "- Authorised representative (if any, Art. 18): not appointed",
    ),
    "",
    "## 3. Responsibility",
    "",
    "This declaration of conformity is issued under the sole responsibility of the manufacturer.",
    "",
    "## 4. Object of the declaration",
    "",
    `${product.name}, version ${input.version}: ${product.intendedPurpose}`,
    "",
    v.block(
      "object",
      `${TODO}: any further identification allowing traceability (for hardware, a photograph where appropriate).`,
    ),
    "",
    "## 5. Statement of conformity",
    "",
    "The object of the declaration described above is in conformity with Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 on horizontal cybersecurity requirements for products with digital elements.",
    "",
    v.block(
      "other-legislation",
      "Other Union harmonisation legislation covered by this single declaration (Art. 28(3)): none",
    ),
    "",
    "## 6. Harmonised standards, common specifications or certification",
    "",
    v.block(
      "standards",
      `${TODO}: references of the harmonised standards, common specifications or cybersecurity certifications in relation to which conformity is declared, or "none".`,
    ),
    "",
    "## 7. Notified body",
    "",
    route ? `Route from the scope triage: ${ROUTE_LABELS[route]} (${routeArticle(scope)}).` : "",
    "",
    v.block("notified-body", notifiedBodyDefault),
    "",
    "## 8. Additional information",
    "",
    v.block(
      "signature",
      [
        `Signed for and on behalf of: ${product.manufacturer.name}`,
        "",
        `Place and date of issue: ${TODO}`,
        "",
        `Name, function: ${TODO}`,
        "",
        `Signature: ${TODO}`,
      ].join("\n"),
    ),
    "",
    "## Simplified declaration (Annex VI)",
    "",
    "Where the product is shipped with the simplified declaration instead (Art. 13(20)):",
    "",
    v.block(
      "simplified-declaration",
      `> Hereby, ${product.manufacturer.name} declares that the product with digital elements type ${product.name} is in compliance with Regulation (EU) 2024/2847. The full text of the EU declaration of conformity is available at the following internet address: ${TODO}`,
    ),
    "",
    "## CE marking (Art. 30(1))",
    "",
    "For software, the CE marking is affixed to this declaration or to the website accompanying the product, in a section consumers can reach easily and directly. Affix it only after the conformity assessment is complete.",
    "",
  ].join("\n");
}
