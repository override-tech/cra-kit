import { describe, expect, it } from "vitest";
import { addMonths } from "./dates";
import { reportingDeadlines, stageState } from "./reporting";
import { assessCraScope, type CraScopeAnswers } from "./scope";
import { documentationRetainedUntil, supportPeriodProblems, updateAvailableUntil } from "./support";

const desktop: CraScopeAnswers = {
  distribution: "desktop_app",
  availableInEu: true,
  monetisation: ["price"],
  isFoss: false,
  isOpenSourceSteward: false,
  coreFunction: "none_of_the_above",
  publicTechnicalDocs: false,
  placedOnMarketAt: null,
  substantialModificationAfterApplication: false,
};

describe("assessCraScope", () => {
  it("puts a paid desktop app in scope on the self-assessment route", () => {
    const result = assessCraScope(desktop);
    expect(result.verdict).toBe("in_scope");
    expect(result.route).toBe("module_a_self_assessment");
    expect(
      result.obligations
        .find((o) => o.key === "report_actively_exploited_and_incidents")
        ?.appliesFrom.toISOString(),
    ).toBe("2026-09-11T00:00:00.000Z");
  });

  it("excludes pure SaaS and non-monetised FOSS, but not monetised FOSS", () => {
    expect(assessCraScope({ ...desktop, distribution: "saas_only" }).reasons).toEqual([
      "recital_12_saas",
    ]);
    expect(assessCraScope({ ...desktop, isFoss: true, monetisation: ["none"] }).verdict).toBe(
      "out_of_scope",
    );
    expect(
      assessCraScope({ ...desktop, isFoss: true, monetisation: ["paid_support_beyond_costs"] })
        .verdict,
    ).toBe("in_scope");
  });

  it("routes a steward to the light regime, all of it from 11 December 2027", () => {
    const result = assessCraScope({
      ...desktop,
      isFoss: true,
      monetisation: ["none"],
      isOpenSourceSteward: true,
    });
    expect(result.verdict).toBe("steward_regime");
    // Art. 71(2) brings forward Art. 14 only; Art. 24(3) applies with the rest.
    for (const o of result.obligations)
      expect(o.appliesFrom.toISOString(), o.key).toBe("2027-12-11T00:00:00.000Z");
  });

  it("escalates class II and lets public FOSS docs self-assess (Art. 32(5))", () => {
    expect(
      assessCraScope({ ...desktop, coreFunction: "firewall_or_intrusion_detection" }).route,
    ).toBe("third_party_module_b_c_or_h");
    expect(
      assessCraScope({
        ...desktop,
        coreFunction: "firewall_or_intrusion_detection",
        isFoss: true,
        publicTechnicalDocs: true,
      }).route,
    ).toBe("module_a_self_assessment");
  });

  it("keeps only Art. 14 for a legacy product until it is substantially modified", () => {
    const legacy = assessCraScope({
      ...desktop,
      placedOnMarketAt: new Date("2025-03-01T00:00:00Z"),
    });
    expect(legacy.legacyProduct).toBe(true);
    expect(legacy.obligations.map((o) => o.article)).toEqual(["14"]);
    const modified = assessCraScope({
      ...desktop,
      placedOnMarketAt: new Date("2025-03-01T00:00:00Z"),
      substantialModificationAfterApplication: true,
    });
    expect(modified.obligations.length).toBeGreaterThan(10);
  });
});

describe("support period and retention (Art. 13)", () => {
  const placed = new Date("2028-01-15T00:00:00Z");

  it("requires five years unless a shorter expected use is declared", () => {
    expect(
      supportPeriodProblems({
        placedOnMarketAt: placed,
        supportEndsAt: new Date("2031-01-15T00:00:00Z"),
      }),
    ).toEqual(["shorter_than_five_years_without_justification"]);
    expect(
      supportPeriodProblems({
        placedOnMarketAt: placed,
        supportEndsAt: new Date("2031-01-15T00:00:00Z"),
        expectedUseYears: 3,
      }),
    ).toEqual([]);
    expect(
      supportPeriodProblems({
        placedOnMarketAt: placed,
        supportEndsAt: new Date("2033-01-15T00:00:00Z"),
      }),
    ).toEqual([]);
  });

  it("keeps each update ten years or to end of support, whichever is later", () => {
    expect(
      updateAvailableUntil(
        new Date("2028-06-01T00:00:00Z"),
        new Date("2033-01-15T00:00:00Z"),
      ).toISOString(),
    ).toBe("2038-06-01T00:00:00.000Z");
    expect(
      updateAvailableUntil(
        new Date("2028-06-01T00:00:00Z"),
        new Date("2040-01-01T00:00:00Z"),
      ).toISOString(),
    ).toBe("2040-01-01T00:00:00.000Z");
    expect(documentationRetainedUntil(placed, new Date("2033-01-15T00:00:00Z")).toISOString()).toBe(
      "2038-01-15T00:00:00.000Z",
    );
  });
});

describe("Art. 14 clocks", () => {
  const aware = new Date("2026-10-01T09:00:00Z");

  it("gives 24h and 72h from awareness, and waits for the fix before the 14-day final report", () => {
    const [early, notification, final] = reportingDeadlines({
      kind: "exploited_vulnerability",
      awareAt: aware,
    });
    expect(early?.dueAt?.toISOString()).toBe("2026-10-02T09:00:00.000Z");
    expect(notification?.dueAt?.toISOString()).toBe("2026-10-04T09:00:00.000Z");
    expect(final).toEqual({ stage: "final_report", dueAt: null, waitingFor: "corrective_measure" });
    const fixed = reportingDeadlines({
      kind: "exploited_vulnerability",
      awareAt: aware,
      correctiveMeasureAt: new Date("2026-10-10T00:00:00Z"),
    });
    expect(fixed[2]?.dueAt?.toISOString()).toBe("2026-10-24T00:00:00.000Z");
  });

  it("gives severe incidents one month after the notification", () => {
    const [, , final] = reportingDeadlines({
      kind: "severe_incident",
      awareAt: aware,
      notificationSentAt: new Date("2026-01-31T00:00:00Z"),
    });
    expect(final?.dueAt?.toISOString()).toBe("2026-02-28T00:00:00.000Z");
  });

  it("reports overdue, due and submitted", () => {
    const [early] = reportingDeadlines({ kind: "severe_incident", awareAt: aware });
    if (!early) throw new Error("missing stage");
    expect(stageState(early, null, new Date("2026-10-02T10:00:00Z"))).toBe("overdue");
    expect(stageState(early, null, new Date("2026-10-01T10:00:00Z"))).toBe("due");
    expect(stageState(early, new Date(), new Date("2026-10-05T00:00:00Z"))).toBe("submitted");
  });

  it("clamps month arithmetic to short months", () => {
    expect(addMonths(new Date("2027-01-31T00:00:00Z"), 1).toISOString()).toBe(
      "2027-02-28T00:00:00.000Z",
    );
  });
});
