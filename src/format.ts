const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const;

/** 2026-10-02 (UTC). */
export function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** 2026-10-02T09:00:00Z (UTC, no milliseconds). */
export function isoDateTime(date: Date): string {
  return `${date.toISOString().slice(0, 19)}Z`;
}

/** "December 2032" - the month-and-year form Art. 13(19) asks for. */
export function monthYear(date: Date): string {
  return `${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
}

/** UTC midnight of the given day. */
export function startOfDay(date: Date): Date {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

/** Escapes text for a Markdown table cell. */
export function cell(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  return String(value).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function mdTable(headers: string[], rows: Array<Array<string | number | null>>): string {
  const lines = [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(cell).join(" | ")} |`),
  ];
  return lines.join("\n");
}

/** Left-aligned plain-text columns for terminal output. */
export function textTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const line = (cols: string[]) =>
    cols
      .map((c, i) => (i === cols.length - 1 ? c : c.padEnd(widths[i] ?? 0)))
      .join("  ")
      .trimEnd();
  return [line(headers), ...rows.map(line)].join("\n");
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/** Stable, locale-independent string comparison for deterministic output. */
export function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function humanize(slug: string): string {
  const text = slug.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
