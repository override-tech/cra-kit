import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli";
import { EXIT } from "../src/errors";
import type { FetchLike } from "../src/scan/net";
import { CLI_VERSION } from "../src/version";
import { failingFetch, mockFetch, osvRoutes, VALID } from "./helpers";

const NOW = "2026-10-02T09:00:00Z";

/** A project with an npm lockfile (lodash 4.17.20) and requirements.txt (requests 2.19.0). */
function project(config: string | null = `${VALID}  version: "2.3.0"\n`): string {
  const dir = mkdtempSync(join(tmpdir(), "cra-cli-"));
  if (config !== null) writeFileSync(join(dir, "cra.yml"), config);
  writeFileSync(
    join(dir, "package-lock.json"),
    JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { lodash: "^4.17.0" } },
        "node_modules/lodash": { version: "4.17.20", license: "MIT" },
      },
    }),
  );
  writeFileSync(join(dir, "requirements.txt"), "requests==2.19.0\n");
  return dir;
}

async function cra(cwd: string, args: string[], fetch: FetchLike = mockFetch(osvRoutes())) {
  let stdout = "";
  let stderr = "";
  const code = await run([...args, "--now", NOW], {
    stdout: (t) => {
      stdout += t;
    },
    stderr: (t) => {
      stderr += t;
    },
    env: { PATH: "" },
    fetch,
    cwd,
    retryDelayMs: 0,
  });
  return { code, stdout, stderr };
}

const read = (dir: string, file: string) => readFileSync(join(dir, file), "utf8");

describe("cra all", () => {
  it("exits 2 when a finding is in CISA KEV and writes the records, summary and outputs", async () => {
    const dir = project();
    const { code, stdout } = await cra(dir, [
      "all",
      "--summary",
      "summary.md",
      "--outputs",
      "outputs.txt",
    ]);
    expect(code).toBe(EXIT.findings);
    expect(stdout).toContain("findings exceed scan.failOn = kev");
    expect(read(dir, "docs/compliance/index.md")).toContain("| Version | 2.3.0 |");
    expect(JSON.parse(read(dir, "docs/compliance/scan.json")).summary.kev).toBe(1);
    expect(JSON.parse(read(dir, "docs/compliance/sbom.cdx.json")).components).toHaveLength(2);
    expect(read(dir, "summary.md")).toContain("| high 7.2 | yes | [GHSA-35jh-r3h4-6jhm]");
    expect(read(dir, "outputs.txt")).toContain("exit-code=2\n");
    expect(read(dir, "outputs.txt")).toContain("output-dir=docs/compliance\n");
  });

  it("follows --fail-on over scan.failOn", async () => {
    const dir = project();
    expect((await cra(dir, ["all", "--fail-on", "none"])).code).toBe(EXIT.ok);
    expect((await cra(dir, ["all", "--fail-on", "sometimes"])).code).toBe(EXIT.usage);
  });

  it("exits 3 when OSV is unreachable, still writing the records", async () => {
    const dir = project();
    const { code, stderr } = await cra(dir, ["all"], failingFetch);
    expect(code).toBe(EXIT.network);
    expect(stderr).toContain("--offline");
    expect(JSON.parse(read(dir, "docs/compliance/scan.json")).status).toBe("error");
    expect(read(dir, "docs/compliance/index.md")).toContain("not performed");
  });

  it("runs --offline without network access", async () => {
    const dir = project();
    const { code } = await cra(dir, ["all", "--offline"], failingFetch);
    expect(code).toBe(EXIT.ok);
    expect(JSON.parse(read(dir, "docs/compliance/scan.json")).status).toBe("skipped");
  });

  it("takes the product version from --version and refuses to guess it", async () => {
    const dir = project(VALID);
    const missing = await cra(dir, ["all", "--offline"]);
    expect(missing.code).toBe(EXIT.usage);
    expect(missing.stderr).toContain("product version is unknown");
    expect((await cra(dir, ["all", "--offline", "--version", "9.9.9"])).code).toBe(EXIT.ok);
    expect(read(dir, "docs/compliance/index.md")).toContain("| Version | 9.9.9 |");
  });
});

describe("cra docs", () => {
  it("writes the records even when OSV is unreachable", async () => {
    const dir = project();
    const { code, stderr } = await cra(dir, ["docs"], failingFetch);
    expect(code).toBe(EXIT.ok);
    expect(stderr).toContain("vulnerability scan not performed");
    expect(read(dir, "docs/compliance/technical-documentation.md")).toContain(
      "Vulnerability scan not performed",
    );
  });
});

describe("cra scan", () => {
  it("prints findings as JSON and applies the threshold", async () => {
    const { code, stdout } = await cra(project(), ["scan", "--json"]);
    expect(code).toBe(EXIT.findings);
    const body = JSON.parse(stdout);
    expect(body.exceedsThreshold).toBe(true);
    expect(body.findings.map((f: { id: string }) => f.id)).toEqual([
      "GHSA-35jh-r3h4-6jhm",
      "GHSA-x84v-xcm2-53pg",
      "GHSA-29mw-wpgm-hmr9",
    ]);
  });

  it("scans an existing CycloneDX file", async () => {
    const dir = project();
    writeFileSync(
      join(dir, "external.cdx.json"),
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [{ type: "library", name: "requests", purl: "pkg:pypi/requests@2.19.0" }],
      }),
    );
    const { code, stdout } = await cra(dir, ["scan", "--sbom", "external.cdx.json"]);
    expect(code).toBe(EXIT.ok);
    expect(stdout).toContain("GHSA-x84v-xcm2-53pg");
  });
});

describe("usage and configuration errors", () => {
  it("exits 1 for a missing or invalid cra.yml", async () => {
    const missing = await cra(project(null), ["scope"]);
    expect(missing.code).toBe(EXIT.usage);
    expect(missing.stderr).toContain("run `cra init`");
    const invalid = await cra(project("product:\n  name: x\n"), ["scope"]);
    expect(invalid.code).toBe(EXIT.usage);
    expect(invalid.stderr).toMatch(/cra\.yml:\d+:\d+ product\.manufacturer is required/);
  });

  it("exits 1 for unknown commands, unknown flags and flags of other commands", async () => {
    const dir = project();
    expect((await cra(dir, ["deploy"])).code).toBe(EXIT.usage);
    expect((await cra(dir, ["scope", "--verbose"])).code).toBe(EXIT.usage);
    const misplaced = await cra(dir, ["scope", "--force"]);
    expect(misplaced.code).toBe(EXIT.usage);
    expect(misplaced.stderr).toContain("--force does not apply to `cra scope`");
  });

  it("prints its own version with a bare --version", async () => {
    const { code, stdout } = await cra(project(), ["--version"]);
    expect(code).toBe(EXIT.ok);
    expect(stdout).toBe(`${CLI_VERSION}\n`);
  });
});

describe("cra init", () => {
  it("writes a template that cra accepts and refuses to overwrite without --force", async () => {
    const dir = project(null);
    expect((await cra(dir, ["init"])).code).toBe(EXIT.ok);
    expect(existsSync(join(dir, "cra.yml"))).toBe(true);
    const scope = await cra(dir, ["scope", "--json"]);
    expect(scope.code).toBe(EXIT.ok);
    expect(JSON.parse(scope.stdout).verdict).toBe("in_scope");
    expect(scope.stderr).toContain("TODO placeholders");
    const again = await cra(dir, ["init"]);
    expect(again.code).toBe(EXIT.usage);
    expect(again.stderr).toContain("--force");
    expect((await cra(dir, ["init", "--force"])).code).toBe(EXIT.ok);
  });
});

describe("cra clock", () => {
  it("prints Art. 14 deadlines and their state at --now", async () => {
    const { code, stdout } = await cra(project(), [
      "clock",
      "--kind",
      "exploited_vulnerability",
      "--aware",
      "2026-10-01T08:00:00Z",
      "--json",
    ]);
    expect(code).toBe(EXIT.ok);
    expect(JSON.parse(stdout).deadlines).toEqual([
      { stage: "early_warning", dueAt: "2026-10-02T08:00:00Z", state: "overdue", waitingFor: null },
      { stage: "notification", dueAt: "2026-10-04T08:00:00Z", state: "due", waitingFor: null },
      {
        stage: "final_report",
        dueAt: null,
        state: "not_applicable",
        waitingFor: "corrective_measure",
      },
    ]);
  });

  it("rejects malformed times and kinds", async () => {
    const dir = project();
    expect((await cra(dir, ["clock", "--kind", "breach", "--aware", NOW])).code).toBe(EXIT.usage);
    expect(
      (await cra(dir, ["clock", "--kind", "severe_incident", "--aware", "yesterday"])).code,
    ).toBe(EXIT.usage);
  });
});
