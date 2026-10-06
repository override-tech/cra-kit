import { CORE_FUNCTIONS } from "./config";
import { addYears, DISTRIBUTION_MODELS, MONETISATION } from "./rules";

/** Wraps a list of options into YAML comment lines of at most ~96 characters. */
function optionLines(prefix: string, options: readonly string[]): string {
  const lines: string[] = [];
  let line = prefix;
  for (const [i, option] of options.entries()) {
    const piece = `${option}${i < options.length - 1 ? "," : ""}`;
    if (line.length + piece.length + 1 > 96) {
      lines.push(line);
      line = prefix;
    }
    line += `${line.endsWith(" ") ? "" : " "}${piece}`;
  }
  lines.push(line);
  return lines.join("\n");
}

/** The commented cra.yml `cra init` writes. Every answer that drives a legal conclusion says REVIEW. */
export function configTemplate(productName: string, now: Date): string {
  const end = addYears(now, 5);
  const supportEndsAt = `${end.getUTCFullYear()}-${String(end.getUTCMonth() + 1).padStart(2, "0")}`;
  return `# cra.yml - Cyber Resilience Act (Regulation (EU) 2024/2847) facts about this product.
# cra turns them into the scope verdict, the SBOM, the vulnerability scan and the
# document templates in output.dir. Replace every TODO; check every answer marked REVIEW,
# because the scope verdict and the obligations follow from them.

product:
  name: ${JSON.stringify(productName)}
  # version: "1.2.3"   # omit to take it from --version or the git tag (v1.2.3 -> 1.2.3)
  manufacturer:
    name: "TODO legal name of the manufacturer"
    address: "TODO street, postcode, city, country"
    email: "TODO@example.com"
    # website: "https://example.com"

  # REVIEW: how the product reaches users. One of:
${optionLines("  #  ", DISTRIBUTION_MODELS)}
  distribution: desktop_app

  # REVIEW: the core function, checked against Annex III/IV as described in Implementing
  # Regulation (EU) 2025/2392. Classify by what the product is for, not by side features.
${optionLines("  #  ", CORE_FUNCTIONS)}
  coreFunction: none_of_the_above

  # REVIEW: how the product is monetised (Recital 15). Any of:
${optionLines("  #  ", MONETISATION)}
  monetisation: [price]
  availableInEu: true
  isFoss: false                 # free and open-source software
  isOpenSourceSteward: false    # a legal person sustaining FOSS for commercial use (Art. 3(14))
  publicTechnicalDocs: false    # technical documentation is public (Art. 32(5), FOSS only)

  # REVIEW: first placed on the EU market (YYYY-MM-DD or YYYY-MM), if it already is.
  # Products placed before 11 December 2027 only owe Art. 14 reporting until they are
  # substantially modified (Art. 69(2)-(3)).
  # placedOnMarketAt: 2025-03
  substantialModificationAfterApplication: false

  intendedPurpose: "TODO what the product does, for whom, and in which environment it runs."

  # REVIEW: end of the support period (YYYY-MM): at least five years after placing on the
  # market unless the product is expected to be used for less (Art. 13(8)).
  supportEndsAt: ${supportEndsAt}
  # expectedUseYears: 3         # only to justify a support period shorter than five years

  # Single point of contact for vulnerability reports (Art. 13(17), Annex I Part II(6)).
  securityContact:
    email: "security@TODO.example"
    # url: "https://example.com/security"          # CVD policy page; security.txt Policy
    # pgpKey: "https://example.com/pgp-key.asc"    # or a 40-hex-digit OpenPGP fingerprint

  # Languages of the user information (Annex II) and security.txt Preferred-Languages.
  languages: [en]

sbom:
  paths: ["."]          # directories (or lockfiles) to read; JS monorepo packages work too
  includeDev: false     # list development-only dependencies (scope "excluded")
  generator: auto       # auto: syft when on PATH, else the lockfiles | syft | builtin

scan:
  failOn: kev           # kev | critical | high | none (KEV-listed findings fail every level but none)

output:
  dir: docs/compliance
`;
}
