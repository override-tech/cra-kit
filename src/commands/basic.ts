import { existsSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";
import type { ProductConfig } from "../config";
import { EXIT, UsageError } from "../errors";
import { humanize, isoDate, isoDateTime, textTable } from "../format";
import { asRecord, asString, isOneOf } from "../guards";
import {
  articleRef,
  CLASS_LABELS,
  OBLIGATION_LABELS,
  REASON_LABELS,
  ROUTE_LABELS,
  routeArticle,
  VERDICT_LABELS,
} from "../labels";
import {
  assessScope,
  displayPath,
  type GlobalOptions,
  type Io,
  loadProject,
  resolveNow,
} from "../project";
import {
  type CraScopeResult,
  MAIN_OBLIGATIONS_FROM,
  REPORTING_APPLIES_FROM,
  type ReportKind,
  reportingApplies,
  reportingDeadlines,
  stageState,
} from "../rules";
import { configTemplate } from "../template";

/** Product name for the template: from the package manifest, else the directory name. */
function guessProductName(cwd: string): string {
  const read = (file: string) => {
    try {
      return readFileSync(resolve(cwd, file), "utf8");
    } catch {
      return null;
    }
  };
  const pkg = read("package.json");
  if (pkg) {
    try {
      const name = asString(asRecord(JSON.parse(pkg)).name);
      if (name) return name;
    } catch {
      // fall through
    }
  }
  for (const [file, table] of [
    ["Cargo.toml", "package"],
    ["pyproject.toml", "project"],
  ] as const) {
    const text = read(file);
    if (!text) continue;
    try {
      const name = asString(asRecord(parseToml(text)[table]).name);
      if (name) return name;
    } catch {
      // fall through
    }
  }
  return basename(cwd);
}

export async function initCommand(options: GlobalOptions, io: Io, force: boolean): Promise<number> {
  const cwd = resolve(io.cwd, options.cwd ?? ".");
  const path = resolve(cwd, options.config ?? "cra.yml");
  const display = displayPath(io.cwd, path);
  if (existsSync(path) && !force) {
    throw new UsageError(`${display} already exists; pass --force to overwrite it`);
  }
  await writeFile(path, configTemplate(guessProductName(cwd), resolveNow(options, io.env).now));
  if (options.json) io.stdout(`${JSON.stringify({ written: display })}\n`);
  else if (!options.quiet) {
    io.stdout(
      `Wrote ${display}.\n\nNext:\n` +
        "  1. Replace the TODO values and check every answer marked REVIEW.\n" +
        "  2. Add .cra-cache/ to .gitignore (vulnerability feed cache).\n" +
        "  3. Run `cra scope`, then `cra all` (or add the GitHub Action).\n",
    );
  }
  return EXIT.ok;
}

export function scopeNotes(product: ProductConfig, scope: CraScopeResult): string[] {
  const notes: string[] = [];
  if (scope.verdict === "in_scope") {
    const placed = product.placedOnMarketAt;
    if (placed === null) {
      notes.push(
        `Not yet on the market. Placed before ${isoDate(MAIN_OBLIGATIONS_FROM)} and not substantially modified afterwards, it would only owe Art. 14 reporting (Art. 69(2)-(3)); placed on or after that date, every obligation applies.`,
      );
    } else if (placed.getTime() < MAIN_OBLIGATIONS_FROM.getTime() && !scope.legacyProduct) {
      notes.push(
        `Placed on the market on ${isoDate(placed)} but substantially modified from ${isoDate(MAIN_OBLIGATIONS_FROM)}: all obligations apply (Art. 69(2)).`,
      );
    }
    if (scope.legacyProduct) {
      notes.push(
        "A change that affects compliance with Annex I Part I or the intended purpose is a substantial modification (Art. 3(30)) and ends the legacy status.",
      );
    }
    notes.push(
      `Art. 14 reporting applies from ${isoDate(REPORTING_APPLIES_FROM)}, also to products already on the market (Art. 69(3)).`,
    );
  }
  notes.push("Triage with article references, not legal advice.");
  return notes;
}

export function scopeJson(product: ProductConfig, scope: CraScopeResult) {
  return {
    product: product.name,
    verdict: scope.verdict,
    reasons: scope.reasons.map((key) => ({ key, text: REASON_LABELS[key] ?? key })),
    productClass: scope.productClass,
    route: scope.route,
    legacyProduct: scope.legacyProduct,
    obligations: scope.obligations.map((o) => ({
      key: o.key,
      article: o.article,
      appliesFrom: isoDate(o.appliesFrom),
      text: OBLIGATION_LABELS[o.key] ?? humanize(o.key),
    })),
    notes: scopeNotes(product, scope),
  };
}

export function scopeText(product: ProductConfig, scope: CraScopeResult): string {
  const lines = [
    `CRA scope - ${product.name} (Regulation (EU) 2024/2847)`,
    "",
    `Verdict:  ${VERDICT_LABELS[scope.verdict]}`,
    `Class:    ${CLASS_LABELS[scope.productClass]}`,
    `Route:    ${scope.route ? `${ROUTE_LABELS[scope.route]} (${routeArticle(scope)})` : "not applicable"}`,
  ];
  if (scope.reasons.length > 0) {
    lines.push("", "Why:", ...scope.reasons.map((r) => `  - ${REASON_LABELS[r] ?? r}`));
  }
  if (scope.obligations.length > 0) {
    lines.push(
      "",
      "Obligations:",
      textTable(
        ["  ARTICLE", "FROM", "OBLIGATION"],
        scope.obligations.map((o) => [
          `  ${articleRef(o.article)}`,
          isoDate(o.appliesFrom),
          OBLIGATION_LABELS[o.key] ?? humanize(o.key),
        ]),
      ),
    );
  }
  lines.push("", "Notes:", ...scopeNotes(product, scope).map((n) => `  - ${n}`));
  return `${lines.join("\n")}\n`;
}

export async function scopeCommand(options: GlobalOptions, io: Io): Promise<number> {
  const project = await loadProject(options, io);
  const scope = assessScope(project);
  const product = project.config.product;
  if (options.json) io.stdout(`${JSON.stringify(scopeJson(product, scope), null, 2)}\n`);
  else if (!options.quiet) io.stdout(scopeText(product, scope));
  return EXIT.ok;
}

function parseInstant(value: string | undefined, flag: string): Date | null {
  if (value === undefined) return null;
  const date = new Date(value);
  if (!/^\d{4}-\d{2}-\d{2}/.test(value) || Number.isNaN(date.getTime())) {
    throw new UsageError(
      `${flag} expects an ISO 8601 time such as 2026-10-01T09:00:00Z, got "${value}"`,
    );
  }
  return date;
}

function untilText(from: Date, to: Date): string {
  const minutes = Math.round(Math.abs(to.getTime() - from.getTime()) / 60_000);
  const d = Math.floor(minutes / 1440);
  const h = Math.floor((minutes % 1440) / 60);
  const m = minutes % 60;
  const span = d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
  return to.getTime() >= from.getTime() ? `in ${span}` : `${span} ago`;
}

export interface ClockArgs {
  kind?: string;
  aware?: string;
  fixed?: string;
  notified?: string;
  warned?: string;
}

export function clockCommand(options: GlobalOptions, io: Io, args: ClockArgs): number {
  const kinds: readonly ReportKind[] = ["exploited_vulnerability", "severe_incident"];
  const kind = args.kind;
  if (!isOneOf(kinds, kind)) throw new UsageError(`--kind must be one of: ${kinds.join(", ")}`);
  const awareAt = parseInstant(args.aware, "--aware");
  if (!awareAt) throw new UsageError("--aware <ISO time> is required: when you became aware");
  const fixedAt = parseInstant(args.fixed, "--fixed");
  const notifiedAt = parseInstant(args.notified, "--notified");
  const warnedAt = parseInstant(args.warned, "--warned");
  if (fixedAt && kind !== "exploited_vulnerability") {
    throw new UsageError("--fixed only applies to --kind exploited_vulnerability");
  }
  const now = resolveNow(options, io.env).now;
  const deadlines = reportingDeadlines({
    kind,
    awareAt,
    correctiveMeasureAt: fixedAt,
    notificationSentAt: notifiedAt,
  });
  const submitted = { early_warning: warnedAt, notification: notifiedAt, final_report: null };
  const rows = deadlines.map((d) => ({
    stage: d.stage,
    dueAt: d.dueAt ? isoDateTime(d.dueAt) : null,
    state: stageState(d, submitted[d.stage], now),
    waitingFor: d.waitingFor ?? null,
  }));
  const applies = reportingApplies(awareAt);
  if (options.json) {
    io.stdout(
      `${JSON.stringify({ kind, awareAt: isoDateTime(awareAt), now: isoDateTime(now), applies, deadlines: rows }, null, 2)}\n`,
    );
    return EXIT.ok;
  }
  if (options.quiet) return EXIT.ok;
  const table = textTable(
    ["STAGE", "DUE (UTC)", "STATE"],
    deadlines.map((d, i) => {
      const row = rows[i];
      const state = row?.state ?? "";
      return [
        humanize(d.stage).toLowerCase(),
        row?.dueAt ?? "-",
        d.dueAt === null
          ? d.waitingFor === "corrective_measure"
            ? "starts when a fix or mitigation is available (--fixed)"
            : "starts when the notification is sent (--notified)"
          : state === "submitted"
            ? "submitted"
            : `${state} (${untilText(now, d.dueAt)})`,
      ];
    }),
  );
  io.stdout(
    [
      `Art. 14 clock - ${kind === "exploited_vulnerability" ? "actively exploited vulnerability (Art. 14(2))" : "severe incident (Art. 14(4))"}`,
      `Aware since ${isoDateTime(awareAt)}; now ${isoDateTime(now)}`,
      "",
      table,
      "",
      applies
        ? "Submit via the ENISA Single Reporting Platform to the CSIRT of your main establishment (Art. 14(7), Art. 16)."
        : `Awareness predates ${isoDate(REPORTING_APPLIES_FROM)}, when Art. 14 starts to apply: these deadlines are informational.`,
      "",
    ].join("\n"),
  );
  return EXIT.ok;
}
