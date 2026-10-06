import {
  type ConformityRoute,
  type CoreFunction,
  classify,
  conformityRoute,
  type ProductClass,
} from "./classification";
import { MAIN_OBLIGATIONS_FROM, REPORTING_APPLIES_FROM } from "./dates";

/**
 * Is this product in scope of the CRA, and what follows? Triage, not legal
 * advice: every outcome cites the provision so the vendor can check it.
 */
export const DISTRIBUTION_MODELS = [
  "desktop_app",
  "mobile_app",
  "browser_extension",
  "self_hosted_server",
  "plugin_or_extension",
  "library_or_package",
  "firmware_or_device",
  "saas_only",
] as const;
export type DistributionModel = (typeof DISTRIBUTION_MODELS)[number];

export const MONETISATION = [
  "price",
  "paid_support_beyond_costs",
  "subscription_or_licence",
  "ads_or_data_monetisation",
  "donations_beyond_costs",
  "none",
] as const;
export type Monetisation = (typeof MONETISATION)[number];

export interface CraScopeAnswers {
  distribution: DistributionModel;
  /** Made available on the EU market at all. */
  availableInEu: boolean;
  monetisation: Monetisation[];
  /** Free and open-source software. */
  isFoss: boolean;
  /** A legal person that systematically sustains FOSS intended for commercial activities (Art. 3(14)). */
  isOpenSourceSteward: boolean;
  coreFunction: CoreFunction;
  /** Technical documentation is public (Art. 32(5)). */
  publicTechnicalDocs: boolean;
  /** First placed on the EU market, if already. */
  placedOnMarketAt: Date | null;
  /** Substantially modified since, or planned to be after 11 Dec 2027. */
  substantialModificationAfterApplication: boolean;
}

export type CraVerdict = "in_scope" | "out_of_scope" | "steward_regime";

export interface CraObligation {
  key: string;
  article: string;
  appliesFrom: Date;
}

export interface CraScopeResult {
  verdict: CraVerdict;
  reasons: string[];
  productClass: ProductClass;
  route: ConformityRoute | null;
  obligations: CraObligation[];
  /** Products already on the market before 11 Dec 2027 (Art. 69(2)). */
  legacyProduct: boolean;
}

const MANUFACTURER_OBLIGATIONS: Array<Omit<CraObligation, "appliesFrom">> = [
  { key: "essential_requirements", article: "13(1), Annex I Part I" },
  { key: "risk_assessment", article: "13(2)-(4)" },
  { key: "due_diligence_components", article: "13(5)" },
  { key: "vulnerability_handling", article: "13(6), Annex I Part II" },
  { key: "sbom", article: "Annex I Part II(1)" },
  { key: "support_period", article: "13(8), 13(19)" },
  { key: "updates_available_10_years", article: "13(9)" },
  { key: "technical_documentation", article: "13(12)-(13), 31, Annex VII" },
  { key: "conformity_assessment", article: "13(12), 32" },
  { key: "eu_declaration_of_conformity", article: "28, Annex V" },
  { key: "ce_marking", article: "29-30" },
  { key: "user_information", article: "13(18), Annex II" },
  { key: "single_point_of_contact", article: "13(17)" },
];

export function assessCraScope(answers: CraScopeAnswers): CraScopeResult {
  const productClass = classify(answers.coreFunction);
  const reasons: string[] = [];

  if (!answers.availableInEu) {
    return {
      verdict: "out_of_scope",
      reasons: ["not_on_eu_market"],
      productClass,
      route: null,
      obligations: [],
      legacyProduct: false,
    };
  }
  if (answers.distribution === "saas_only") {
    // Recital 12: cloud services developed outside the responsibility of a
    // product manufacturer are NIS2's business, not the CRA's.
    return {
      verdict: "out_of_scope",
      reasons: ["recital_12_saas"],
      productClass,
      route: null,
      obligations: [],
      legacyProduct: false,
    };
  }
  const monetised = answers.monetisation.some((m) => m !== "none");
  if (!monetised) {
    if (answers.isOpenSourceSteward) {
      return {
        verdict: "steward_regime",
        reasons: ["art_24_steward"],
        productClass,
        route: null,
        obligations: [
          { key: "cybersecurity_policy", article: "24(1)", appliesFrom: MAIN_OBLIGATIONS_FROM },
          {
            key: "cooperate_with_authorities",
            article: "24(2)",
            appliesFrom: MAIN_OBLIGATIONS_FROM,
          },
          {
            key: "report_actively_exploited",
            article: "24(3), 14(1)",
            // Art. 71(2) brings forward Art. 14 for manufacturers only: Art. 24(3)
            // applies with the rest of the Regulation.
            appliesFrom: MAIN_OBLIGATIONS_FROM,
          },
        ],
        legacyProduct: false,
      };
    }
    reasons.push(answers.isFoss ? "recital_18_non_monetised_foss" : "no_commercial_activity");
    return {
      verdict: "out_of_scope",
      reasons,
      productClass,
      route: null,
      obligations: [],
      legacyProduct: false,
    };
  }

  const legacyProduct =
    answers.placedOnMarketAt !== null &&
    answers.placedOnMarketAt.getTime() < MAIN_OBLIGATIONS_FROM.getTime() &&
    !answers.substantialModificationAfterApplication;
  if (legacyProduct) reasons.push("art_69_2_legacy_until_substantial_modification");

  const obligations: CraObligation[] = [
    {
      key: "report_actively_exploited_and_incidents",
      article: "14",
      appliesFrom: REPORTING_APPLIES_FROM,
    },
    ...(legacyProduct
      ? []
      : MANUFACTURER_OBLIGATIONS.map((o) => ({ ...o, appliesFrom: MAIN_OBLIGATIONS_FROM }))),
  ];
  if (answers.distribution === "mobile_app") reasons.push("recital_11_backend_is_rdps");
  return {
    verdict: "in_scope",
    reasons,
    productClass,
    route: conformityRoute(productClass, answers.isFoss && answers.publicTechnicalDocs),
    obligations,
    legacyProduct,
  };
}
