/**
 * Regulation (EU) 2024/2847, Art. 71(2): the regulation applies from
 * 11 December 2027, except Art. 14 (reporting) from 11 September 2026 and
 * Chapter IV (notified bodies) from 11 June 2026.
 */
export const REPORTING_APPLIES_FROM = new Date("2026-09-11T00:00:00Z");
export const NOTIFIED_BODIES_FROM = new Date("2026-06-11T00:00:00Z");
export const MAIN_OBLIGATIONS_FROM = new Date("2027-12-11T00:00:00Z");

/** Add whole calendar months in UTC, clamping to the last day of short months. */
export function addMonths(date: Date, months: number): Date {
  const result = new Date(date.getTime());
  const day = result.getUTCDate();
  result.setUTCDate(1);
  result.setUTCMonth(result.getUTCMonth() + months);
  const lastDay = new Date(
    Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0),
  ).getUTCDate();
  result.setUTCDate(Math.min(day, lastDay));
  return result;
}

export function addYears(date: Date, years: number): Date {
  return addMonths(date, years * 12);
}

export const laterOf = (a: Date, b: Date): Date => (a.getTime() >= b.getTime() ? a : b);
