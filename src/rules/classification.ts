/**
 * Annex III (important products, classes I and II) and Annex IV (critical
 * products), as described technically by Implementing Regulation (EU)
 * 2025/2392. A product is classified by its *core functionality*: a word
 * processor with a built-in VPN client is not a VPN product.
 */

export const IMPORTANT_CLASS_I = [
  "identity_management_or_privileged_access",
  "standalone_browser",
  "password_manager",
  "malware_protection",
  "vpn",
  "network_management",
  "siem",
  "boot_manager",
  "pki_or_certificate_issuance",
  "physical_or_virtual_network_interface",
  "operating_system",
  "router_modem_switch",
  "microprocessor_with_security_functions",
  "microcontroller_with_security_functions",
  "asic_fpga_with_security_functions",
  "smart_home_general_purpose_assistant",
  "smart_home_security_product",
  "connected_toy_with_interaction_or_location",
  "personal_wearable_health_or_child",
] as const;

export const IMPORTANT_CLASS_II = [
  "hypervisor_or_container_runtime",
  "firewall_or_intrusion_detection",
  "tamper_resistant_microprocessor",
  "tamper_resistant_microcontroller",
] as const;

export const CRITICAL = [
  "hardware_security_box",
  "smart_meter_gateway",
  "smartcard_or_secure_element",
] as const;

export type CoreFunction =
  | (typeof IMPORTANT_CLASS_I)[number]
  | (typeof IMPORTANT_CLASS_II)[number]
  | (typeof CRITICAL)[number]
  | "none_of_the_above";

export type ProductClass = "default" | "important_i" | "important_ii" | "critical";

export function classify(coreFunction: CoreFunction): ProductClass {
  if ((IMPORTANT_CLASS_I as readonly string[]).includes(coreFunction)) return "important_i";
  if ((IMPORTANT_CLASS_II as readonly string[]).includes(coreFunction)) return "important_ii";
  if ((CRITICAL as readonly string[]).includes(coreFunction)) return "critical";
  return "default";
}

/**
 * Art. 32. Class I may self-assess only when harmonised standards, common
 * specifications or a European certification scheme are applied in full;
 * otherwise, and always for class II, a notified body is involved. Critical
 * products need a European cybersecurity certificate where one is required,
 * else follow the class II routes. FOSS class I/II products whose technical
 * documentation is public may self-assess (Art. 32(5)).
 */
export type ConformityRoute =
  | "module_a_self_assessment"
  | "module_a_if_standards_applied_else_third_party"
  | "third_party_module_b_c_or_h"
  | "eu_certification_or_third_party";

export function conformityRoute(
  productClass: ProductClass,
  publicFossDocs = false,
): ConformityRoute {
  switch (productClass) {
    case "default":
      return "module_a_self_assessment";
    case "important_i":
      return publicFossDocs
        ? "module_a_self_assessment"
        : "module_a_if_standards_applied_else_third_party";
    case "important_ii":
      return publicFossDocs ? "module_a_self_assessment" : "third_party_module_b_c_or_h";
    case "critical":
      return "eu_certification_or_third_party";
  }
}
