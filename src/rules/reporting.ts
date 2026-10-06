import { addMonths, REPORTING_APPLIES_FROM } from "./dates";

/**
 * Art. 14 reporting clocks, all running from the moment the manufacturer
 * becomes aware.
 *
 * Actively exploited vulnerability (Art. 14(2)):
 *   early warning within 24h, notification within 72h, final report within
 *   14 days after a corrective or mitigating measure is available.
 * Severe incident (Art. 14(4)):
 *   early warning within 24h, notification within 72h, final report within
 *   one month after the incident notification.
 *
 * All go through the ENISA Single Reporting Platform. Art. 64(10)(a): micro
 * and small enterprises are not fined for missing the 24h early warning -
 * the obligation itself still applies.
 */
export type ReportKind = "exploited_vulnerability" | "severe_incident";
export type ReportStage = "early_warning" | "notification" | "final_report";

const HOUR = 3_600_000;

export interface ClockInput {
  kind: ReportKind;
  awareAt: Date;
  notificationSentAt?: Date | null;
  /** Exploited vulnerabilities only: when a fix or mitigation became available. */
  correctiveMeasureAt?: Date | null;
}

export interface Deadline {
  stage: ReportStage;
  dueAt: Date | null;
  /** Why dueAt is null: the clock has not started yet. */
  waitingFor?: "corrective_measure" | "notification";
}

export function reportingDeadlines(input: ClockInput): Deadline[] {
  const early: Deadline = {
    stage: "early_warning",
    dueAt: new Date(input.awareAt.getTime() + 24 * HOUR),
  };
  const notification: Deadline = {
    stage: "notification",
    dueAt: new Date(input.awareAt.getTime() + 72 * HOUR),
  };
  let final: Deadline;
  if (input.kind === "exploited_vulnerability") {
    final = input.correctiveMeasureAt
      ? {
          stage: "final_report",
          dueAt: new Date(input.correctiveMeasureAt.getTime() + 14 * 24 * HOUR),
        }
      : { stage: "final_report", dueAt: null, waitingFor: "corrective_measure" };
  } else {
    final = input.notificationSentAt
      ? { stage: "final_report", dueAt: addMonths(input.notificationSentAt, 1) }
      : { stage: "final_report", dueAt: null, waitingFor: "notification" };
  }
  return [early, notification, final];
}

export type ClockState = "not_applicable" | "due" | "overdue" | "submitted";

/** Reporting only binds awareness from 11 Sep 2026 onward. */
export function reportingApplies(awareAt: Date): boolean {
  return awareAt.getTime() >= REPORTING_APPLIES_FROM.getTime();
}

export function stageState(deadline: Deadline, submittedAt: Date | null, now: Date): ClockState {
  if (submittedAt) return "submitted";
  if (!deadline.dueAt) return "not_applicable";
  return now.getTime() > deadline.dueAt.getTime() ? "overdue" : "due";
}

export const REPORT_STAGES: readonly ReportStage[] = [
  "early_warning",
  "notification",
  "final_report",
];

/** When the stage was filed with the SRP, per stage; null while pending. */
export type Submissions = Record<ReportStage, Date | null>;

/**
 * Reminder lead times before each deadline, in hours; 0 is the "now overdue"
 * notice. A reminder is sent at most once per stage and lead time.
 */
export const REMINDER_LEAD_HOURS = [12, 2, 0] as const;
export type ReminderLead = (typeof REMINDER_LEAD_HOURS)[number];

export interface ReminderDue {
  stage: ReportStage;
  leadHours: ReminderLead;
  dueAt: Date;
  /** Longer lead times this one makes pointless; record them as sent too. */
  supersedes: ReminderLead[];
}

/**
 * The reminders to send now. For each unsubmitted stage with a running
 * clock, only the most urgent lead time that has been reached counts: a
 * worker that was down through the 12-hour mark and wakes up 90 minutes
 * before the deadline sends the 2-hour reminder, not both.
 */
export function dueReminders(
  deadlines: Deadline[],
  submitted: Submissions,
  sent: ReadonlySet<string>,
  now: Date,
): ReminderDue[] {
  const due: ReminderDue[] = [];
  for (const { stage, dueAt } of deadlines) {
    if (!dueAt || submitted[stage]) continue;
    const reached = REMINDER_LEAD_HOURS.filter(
      (lead) => now.getTime() >= dueAt.getTime() - lead * HOUR,
    );
    const mostUrgent = reached[reached.length - 1];
    if (mostUrgent === undefined || sent.has(reminderKey(stage, mostUrgent))) continue;
    due.push({
      stage,
      leadHours: mostUrgent,
      dueAt,
      supersedes: reached.filter((lead) => lead !== mostUrgent),
    });
  }
  return due;
}

/** Identity of a sent reminder, as the worker stores it. */
export function reminderKey(stage: string, leadHours: number): string {
  return `${stage}:${leadHours}`;
}

export type SubmissionProblem =
  | "already_submitted"
  | "in_the_future"
  | "before_awareness"
  | "early_warning_first"
  | "notification_first"
  | "corrective_measure_first";

/**
 * Whether a stage can be recorded as filed at `at`. The SRP takes the three
 * stages in order, and an exploited vulnerability's final report describes
 * the corrective measure, so it cannot precede one (Art. 14(2)(c)).
 */
export function submissionProblems(
  input: ClockInput & { submitted: Submissions },
  stage: ReportStage,
  at: Date,
  now: Date,
): SubmissionProblem[] {
  const problems: SubmissionProblem[] = [];
  if (input.submitted[stage]) problems.push("already_submitted");
  if (at.getTime() > now.getTime()) problems.push("in_the_future");
  if (at.getTime() < input.awareAt.getTime()) problems.push("before_awareness");
  const earlyWarning = input.submitted.early_warning;
  const notification = input.submitted.notification;
  if (stage === "notification" && (!earlyWarning || at.getTime() < earlyWarning.getTime()))
    problems.push("early_warning_first");
  if (stage === "final_report") {
    if (!notification || at.getTime() < notification.getTime()) problems.push("notification_first");
    if (input.kind === "exploited_vulnerability" && !input.correctiveMeasureAt)
      problems.push("corrective_measure_first");
  }
  return problems;
}
