/**
 * CVSS base scores from vector strings, which is all OSV records carry.
 * v3.x per the FIRST v3.1 specification (section 7), v2 per the v2 guide
 * (section 3.2.1). CVSS v4 needs FIRST's macro-vector tables and is not
 * computed here; callers fall back to the database's qualitative rating.
 */

function metrics(vector: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of vector.split("/")) {
    const [key, value] = part.split(":");
    if (key && value) out.set(key, value);
  }
  return out;
}

/** CVSS v3.1 Roundup: smallest one-decimal number >= input, robust to float error. */
function roundUp(value: number): number {
  const scaled = Math.round(value * 100000);
  return scaled % 10000 === 0 ? scaled / 100000 : (Math.floor(scaled / 10000) + 1) / 10;
}

const AV3: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC3: Record<string, number> = { L: 0.77, H: 0.44 };
const UI3: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA3: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

export function cvss3BaseScore(vector: string): number | null {
  const m = metrics(vector);
  const version = /^CVSS:3\.([01])\//.exec(vector)?.[1];
  if (version === undefined) return null;
  const scope = m.get("S");
  const changed = scope === "C";
  const pr = m.get("PR");
  const prWeight =
    pr === "N"
      ? 0.85
      : pr === "L"
        ? changed
          ? 0.68
          : 0.62
        : pr === "H"
          ? changed
            ? 0.5
            : 0.27
          : undefined;
  const av = AV3[m.get("AV") ?? ""];
  const ac = AC3[m.get("AC") ?? ""];
  const ui = UI3[m.get("UI") ?? ""];
  const c = CIA3[m.get("C") ?? ""];
  const i = CIA3[m.get("I") ?? ""];
  const a = CIA3[m.get("A") ?? ""];
  if (
    (scope !== "U" && scope !== "C") ||
    prWeight === undefined ||
    av === undefined ||
    ac === undefined ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined
  ) {
    return null;
  }
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * prWeight * ui;
  const raw = changed
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  // v3.0 rounds up to one decimal naively; v3.1 fixed floating-point artefacts.
  return version === "1" ? roundUp(raw) : Math.ceil(raw * 10) / 10;
}

const AV2: Record<string, number> = { L: 0.395, A: 0.646, N: 1 };
const AC2: Record<string, number> = { H: 0.35, M: 0.61, L: 0.71 };
const AU2: Record<string, number> = { M: 0.45, S: 0.56, N: 0.704 };
const CIA2: Record<string, number> = { N: 0, P: 0.275, C: 0.66 };

export function cvss2BaseScore(vector: string): number | null {
  const m = metrics(vector.replace(/^\(|\)$/g, ""));
  const av = AV2[m.get("AV") ?? ""];
  const ac = AC2[m.get("AC") ?? ""];
  const au = AU2[m.get("Au") ?? ""];
  const c = CIA2[m.get("C") ?? ""];
  const i = CIA2[m.get("I") ?? ""];
  const a = CIA2[m.get("A") ?? ""];
  if ([av, ac, au, c, i, a].some((x) => x === undefined)) return null;
  const impact = 10.41 * (1 - (1 - (c ?? 0)) * (1 - (i ?? 0)) * (1 - (a ?? 0)));
  const exploitability = 20 * (av ?? 0) * (ac ?? 0) * (au ?? 0);
  const f = impact === 0 ? 0 : 1.176;
  return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * f * 10) / 10;
}

export type Severity = "critical" | "high" | "medium" | "low" | "none" | "unknown";

/** Qualitative rating for a v3 score (also used for v4 and database ratings). */
export function ratingV3(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

/** CVSS v2 has no "critical" band. */
export function ratingV2(score: number): Severity {
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}
