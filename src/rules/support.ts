import { addYears, laterOf } from "./dates";

/**
 * Art. 13(8): the support period is at least five years, unless the product
 * is expected to be in use for less than that, in which case it matches the
 * expected use time. The end date (month and year) is stated at purchase
 * (Art. 13(19)).
 */
export const MIN_SUPPORT_YEARS = 5;

export interface SupportPeriodInput {
  placedOnMarketAt: Date;
  /** Declared end of support. */
  supportEndsAt: Date;
  /** Expected use time in years, when the vendor justifies a shorter period. */
  expectedUseYears?: number;
}

export type SupportProblem = "shorter_than_five_years_without_justification" | "ends_before_placed";

export function supportPeriodProblems(input: SupportPeriodInput): SupportProblem[] {
  if (input.supportEndsAt.getTime() <= input.placedOnMarketAt.getTime())
    return ["ends_before_placed"];
  const minimumYears =
    input.expectedUseYears !== undefined && input.expectedUseYears < MIN_SUPPORT_YEARS
      ? input.expectedUseYears
      : MIN_SUPPORT_YEARS;
  return input.supportEndsAt.getTime() < addYears(input.placedOnMarketAt, minimumYears).getTime()
    ? ["shorter_than_five_years_without_justification"]
    : [];
}

/**
 * Art. 13(9): each security update must remain available for at least ten
 * years after it was issued, or for the remainder of the support period,
 * whichever is longer.
 */
export function updateAvailableUntil(issuedAt: Date, supportEndsAt: Date): Date {
  return laterOf(addYears(issuedAt, 10), supportEndsAt);
}

/**
 * Art. 13(13): technical documentation and the EU declaration of conformity
 * are kept for at least ten years after placing on the market, or for the
 * support period, whichever is longer.
 */
export function documentationRetainedUntil(placedOnMarketAt: Date, supportEndsAt: Date): Date {
  return laterOf(addYears(placedOnMarketAt, 10), supportEndsAt);
}

/**
 * Lead times, in days, of the notices before the support period ends; 0 is
 * the "support has ended" notice. Six months leaves time to extend the period
 * (and update the published date) or to plan the end-of-support notice.
 */
export const SUPPORT_REMINDER_DAYS = [180, 90, 30, 0] as const;
export type SupportReminderDays = (typeof SUPPORT_REMINDER_DAYS)[number];

const DAY = 24 * 60 * 60 * 1000;

/**
 * The support notice to send now, if any: the most urgent lead time reached
 * and not yet sent, plus the longer ones it makes pointless. A worker that
 * was down at the 90-day mark and wakes at 20 days sends the 30-day notice
 * only. Nothing is sent more than a week after support ended.
 */
export function dueSupportReminder(
  supportEndsAt: Date,
  sent: ReadonlySet<number>,
  now: Date,
): { days: SupportReminderDays; supersedes: SupportReminderDays[] } | null {
  const left = supportEndsAt.getTime() - now.getTime();
  if (left < -7 * DAY) return null;
  const reached = SUPPORT_REMINDER_DAYS.filter((days) => left <= days * DAY);
  const days = reached.at(-1);
  if (days === undefined || sent.has(days)) return null;
  return { days, supersedes: reached.filter((d) => d !== days && !sent.has(d)) };
}
