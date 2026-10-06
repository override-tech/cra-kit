import type { ConformityRoute, CraScopeResult, CraVerdict, ProductClass } from "./rules";

export const VERDICT_LABELS: Record<CraVerdict, string> = {
  in_scope: "In scope - manufacturer obligations apply",
  out_of_scope: "Out of scope",
  steward_regime: "Open-source software steward regime (Art. 24)",
};

export const CLASS_LABELS: Record<ProductClass, string> = {
  default: "Default category - core function not listed in Annex III or IV",
  important_i: "Important product, class I (Annex III)",
  important_ii: "Important product, class II (Annex III)",
  critical: "Critical product (Annex IV)",
};

export const ROUTE_LABELS: Record<ConformityRoute, string> = {
  module_a_self_assessment:
    "Internal control (module A, Annex VIII), carried out by the manufacturer",
  module_a_if_standards_applied_else_third_party:
    "Module A only where harmonised standards, common specifications or a certification scheme are applied in full; otherwise module B+C or H with a notified body (Art. 32(2))",
  third_party_module_b_c_or_h:
    "Notified body: EU-type examination (module B+C), full quality assurance (module H), or a certification scheme at level 'substantial' (Art. 32(3))",
  eu_certification_or_third_party:
    "European cybersecurity certificate where required by Art. 8(1), otherwise a procedure under Art. 32(3) (Art. 32(4))",
};

/** Where the route comes from, for citations next to ROUTE_LABELS. */
export function routeArticle(scope: CraScopeResult): string {
  switch (scope.route) {
    case null:
      return "";
    case "module_a_self_assessment":
      // Annex III products reach module A only as FOSS with public documentation.
      return scope.productClass === "default" ? "Art. 32(1)(a)" : "Art. 32(5)";
    case "module_a_if_standards_applied_else_third_party":
      return "Art. 32(2)";
    case "third_party_module_b_c_or_h":
      return "Art. 32(3)";
    case "eu_certification_or_third_party":
      return "Art. 32(4)";
  }
}

/** "13(1), Annex I Part I" -> "Art. 13(1), Annex I Part I"; references to annexes stay bare. */
export function articleRef(article: string): string {
  return /^\d/.test(article) ? `Art. ${article}` : article;
}
export const REASON_LABELS: Record<string, string> = {
  not_on_eu_market:
    "Not made available on the EU market, so the regulation does not apply (Art. 2(1), Art. 3(22)).",
  recital_12_saas:
    "Cloud services designed outside the responsibility of a product manufacturer are covered by NIS2, not the CRA (Recital 12).",
  art_24_steward:
    "A legal person sustaining non-monetised FOSS intended for commercial use is an open-source software steward with light-touch obligations (Art. 3(14), Art. 24).",
  recital_18_non_monetised_foss:
    "Free and open-source software that its manufacturer does not monetise is not supplied in the course of a commercial activity (Recital 18).",
  no_commercial_activity:
    "Without monetisation the product is not supplied in the course of a commercial activity (Art. 3(22), Recital 15).",
  art_69_2_legacy_until_substantial_modification:
    "Placed on the market before 11 December 2027: only Art. 14 reporting applies until the product is substantially modified (Art. 69(2)-(3), Art. 3(30)).",
  recital_11_backend_is_rdps:
    "The backend the mobile app needs to perform its functions is a remote data processing solution and part of the product (Art. 3(2), Recital 11).",
};

export const OBLIGATION_LABELS: Record<string, string> = {
  report_actively_exploited_and_incidents:
    "Report actively exploited vulnerabilities and severe incidents via the ENISA Single Reporting Platform",
  essential_requirements: "Design, develop and produce to the essential cybersecurity requirements",
  risk_assessment: "Document and maintain a cybersecurity risk assessment",
  due_diligence_components: "Exercise due diligence on third-party and open-source components",
  vulnerability_handling: "Handle vulnerabilities effectively for the support period",
  sbom: "Draw up a software bill of materials",
  support_period: "Set a support period of at least five years and state its end month and year",
  updates_available_10_years:
    "Keep each security update available for 10 years or the rest of the support period",
  technical_documentation: "Draw up and maintain the technical documentation",
  conformity_assessment: "Carry out the conformity assessment procedure",
  eu_declaration_of_conformity: "Draw up and sign the EU declaration of conformity",
  ce_marking: "Affix the CE marking",
  user_information: "Provide the information and instructions to the user",
  single_point_of_contact: "Designate a single point of contact for users",
  cybersecurity_policy: "Put in place and document a cybersecurity policy",
  cooperate_with_authorities: "Cooperate with market surveillance authorities",
  report_actively_exploited:
    "Report actively exploited vulnerabilities in the products you sustain",
};
