import { describe, expect, it } from "vitest";
import { parseConfig } from "../src/config";
import { ConfigError } from "../src/errors";
import { configTemplate } from "../src/template";
import { VALID } from "./helpers";

/** The problems a config produces, as one string per problem. */
function problems(text: string): string[] {
  try {
    parseConfig(text, "cra.yml");
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
  return [];
}

describe("cra.yml validation", () => {
  it("accepts a complete file and fills defaults", () => {
    const { config, placeholders } = parseConfig(VALID, "cra.yml");
    expect(placeholders).toEqual([]);
    expect(config.product.supportEndsAt.toISOString()).toBe("2032-12-31T00:00:00.000Z");
    expect(config.product.securityContact.pgpKey).toBe(
      "openpgp4fpr:abcd1234abcd1234abcd1234abcd1234abcd1234",
    );
    expect(config.product.availableInEu).toBe(true);
    expect(config.sbom).toEqual({ paths: ["."], includeDev: false, generator: "auto" });
    expect(config.scan.failOn).toBe("kev");
    expect(config.output.dir).toBe("docs/compliance");
  });

  it("accepts the template cra init writes, flagging its placeholders", () => {
    const { config, placeholders } = parseConfig(
      configTemplate("demo", new Date("2026-10-02T00:00:00Z")),
      "cra.yml",
    );
    expect(config.product.name).toBe("demo");
    expect(config.product.supportEndsAt.toISOString()).toBe("2031-10-31T00:00:00.000Z");
    expect(placeholders).toEqual([
      "product.manufacturer.name",
      "product.manufacturer.address",
      "product.manufacturer.email",
      "product.intendedPurpose",
      "product.securityContact.email",
    ]);
  });

  it("points at the line and suggests the intended key or value", () => {
    const result = problems(
      VALID.replace("  distribution: self_hosted_server", "  distribution: self_hosted")
        .replace("  isFoss: false", "  isFoss: false\n  isFOSS: true")
        .replace("[subscription_or_licence]", "[subscription]"),
    );
    expect(result).toContain(
      'cra.yml:8:17 product.distribution "self_hosted" is not one of: desktop_app, mobile_app, browser_extension, self_hosted_server, plugin_or_extension, library_or_package, firmware_or_device, saas_only (did you mean "self_hosted_server"?)',
    );
    expect(result).toContainEqual(
      expect.stringMatching(
        /^cra\.yml:12:\d+ product\.isFOSS unknown key \(did you mean "isFoss"\?\)$/,
      ),
    );
    expect(result).toContainEqual(
      expect.stringMatching(
        /product\.monetisation\.0 "subscription" is not one of: .* \(did you mean "subscription_or_licence"\?\)$/,
      ),
    );
  });

  it("reports missing and malformed fields together", () => {
    const result = problems(
      VALID.replace("    name: Acme Software sp. z o.o.\n", "")
        .replace("legal@acme.example", "not-an-email")
        .replace("supportEndsAt: 2032-12", "supportEndsAt: 2032")
        .replace("url: https://acme.example/security", "url: http://acme.example/security")
        .replace("[en, pl]", "[english]"),
    );
    expect(result).toEqual([
      expect.stringMatching(
        /^cra\.yml:\d+:\d+ product\.securityContact\.url must be an https:\/\/ URL/,
      ),
      expect.stringMatching(
        /product\.supportEndsAt expected YYYY-MM or YYYY-MM-DD, got number 2032$/,
      ),
      expect.stringMatching(/product\.languages\.0 "english" is not a language tag/),
      expect.stringMatching(/^cra\.yml:4:5 product\.manufacturer\.name is required$/),
      expect.stringMatching(
        /product\.manufacturer\.email expected an email address, got "not-an-email"$/,
      ),
    ]);
  });

  it("rejects combining no monetisation with monetisation", () => {
    expect(problems(VALID.replace("[subscription_or_licence]", "[none, price]"))).toEqual([
      expect.stringContaining('product.monetisation "none" cannot be combined with other values'),
    ]);
  });

  it("reports YAML syntax errors with their position", () => {
    const result = problems("product:\n  name: [unclosed\n");
    expect(result[0]).toMatch(/^cra\.yml:\d+:\d+ /);
  });

  it("refuses an output directory outside the project", () => {
    expect(problems(`${VALID}output:\n  dir: ../elsewhere\n`)).toEqual([
      expect.stringContaining("output.dir must be a path inside the project"),
    ]);
  });
});
