import { describe, expect, it } from "vitest";
import { dueSupportReminder } from "./support";

const END = new Date("2031-12-31T23:59:59.999Z");
const daysBefore = (days: number) => new Date(END.getTime() - days * 24 * 60 * 60 * 1000);

describe("dueSupportReminder", () => {
  it("sends nothing more than six months out", () => {
    expect(dueSupportReminder(END, new Set(), daysBefore(181))).toBeNull();
  });

  it("sends the six-month notice once", () => {
    expect(dueSupportReminder(END, new Set(), daysBefore(170))).toEqual({
      days: 180,
      supersedes: [],
    });
    expect(dueSupportReminder(END, new Set([180]), daysBefore(170))).toBeNull();
  });

  it("after downtime sends only the most urgent notice and marks the skipped ones", () => {
    expect(dueSupportReminder(END, new Set(), daysBefore(20))).toEqual({
      days: 30,
      supersedes: [180, 90],
    });
    expect(dueSupportReminder(END, new Set([180]), daysBefore(20))).toEqual({
      days: 30,
      supersedes: [90],
    });
  });

  it("sends the end notice when support has ended, but not weeks later", () => {
    expect(dueSupportReminder(END, new Set([180, 90, 30]), new Date(END.getTime() + 1000))).toEqual(
      { days: 0, supersedes: [] },
    );
    expect(
      dueSupportReminder(END, new Set(), new Date(END.getTime() + 8 * 24 * 60 * 60 * 1000)),
    ).toBeNull();
  });
});
