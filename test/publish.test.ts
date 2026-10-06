import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli";
import { EXIT } from "../src/errors";
import { VALID } from "./helpers";

interface Captured {
  url: string;
  headers: Record<string, string>;
  form: FormData;
}

/** A project whose `cra all` has already written its records. */
function project({ sbom = true }: { sbom?: boolean } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "cra-publish-"));
  writeFileSync(join(dir, "cra.yml"), `${VALID}  version: "2.3.0"\n`);
  const out = join(dir, "docs", "compliance");
  mkdirSync(out, { recursive: true });
  if (sbom) writeFileSync(join(out, "sbom.cdx.json"), '{"bomFormat":"CycloneDX"}\n');
  writeFileSync(join(out, "index.md"), "# Records\n");
  writeFileSync(join(out, "declaration-of-conformity.md"), "# DoC\n");
  mkdirSync(join(out, "drafts"));
  writeFileSync(join(dir, "acme-backup_2.3.0_linux_amd64.tar.gz"), "binary");
  return dir;
}

async function publish(
  cwd: string,
  args: string[],
  answer: { status: number; body: unknown },
  env: Record<string, string> = { RELEASEKEEP_TOKEN: "crakit_up_secret" },
) {
  const requests: Captured[] = [];
  let stdout = "";
  let stderr = "";
  const code = await run(["publish", ...args], {
    stdout: (t) => {
      stdout += t;
    },
    stderr: (t) => {
      stderr += t;
    },
    env: { PATH: "", ...env },
    fetch: async (url, init) => {
      requests.push({
        url,
        headers: init?.headers as Record<string, string>,
        form: init?.body as FormData,
      });
      return new Response(JSON.stringify(answer.body), { status: answer.status });
    },
    cwd,
    retryDelayMs: 0,
  });
  return { code, stdout, stderr, requests };
}

const archived = {
  status: 201,
  body: { outcome: "created", pageUrl: "https://cra.example/p/acme/backup", public: true },
};

describe("cra publish", () => {
  it("uploads the records and artifacts as one multipart release under the product version", async () => {
    const dir = project();
    const { code, stdout, requests } = await publish(
      dir,
      ["--to", "https://cra.example/", "--artifact", "acme-backup_2.3.0_linux_amd64.tar.gz"],
      archived,
    );
    expect(code).toBe(EXIT.ok);
    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request?.url).toBe("https://cra.example/api/v1/releases");
    expect(request?.headers.authorization).toBe("Bearer crakit_up_secret");
    expect(request?.form.get("version")).toBe("2.3.0");
    const names = request?.form.getAll("files").map((f) => (f as File).name);
    // Top-level records only (the drafts/ folder is not part of the release), plus the artifact.
    expect(names).toEqual([
      "declaration-of-conformity.md",
      "index.md",
      "sbom.cdx.json",
      "artifacts/acme-backup_2.3.0_linux_amd64.tar.gz",
    ]);
    expect(stdout).toContain("https://cra.example/p/acme/backup");
  });

  it("refuses to run without RELEASEKEEP_TOKEN and never accepts the token as a flag", async () => {
    const dir = project();
    const missing = await publish(dir, ["--to", "https://cra.example"], archived, {});
    expect(missing.code).toBe(EXIT.usage);
    expect(missing.stderr).toContain("RELEASEKEEP_TOKEN");
    expect(missing.requests).toHaveLength(0);
    const flag = await publish(dir, ["--token", "x"], archived, {});
    expect(flag.code).toBe(EXIT.usage);
  });

  it("publishes to releasekeep.com unless --to or RELEASEKEEP_URL names another instance", async () => {
    const dir = project();
    const hosted = await publish(dir, [], archived);
    expect(hosted.requests[0]?.url).toBe("https://releasekeep.com/api/v1/releases");
    const own = await publish(dir, [], archived, {
      RELEASEKEEP_TOKEN: "crakit_up_secret",
      RELEASEKEEP_URL: "https://keep.acme.example/",
    });
    expect(own.requests[0]?.url).toBe("https://keep.acme.example/api/v1/releases");
  });

  it("explains a 409: an archived version never changes", async () => {
    const dir = project();
    const { code, stderr } = await publish(dir, ["--to", "https://cra.example"], {
      status: 409,
      body: { title: "Conflict", detail: "Version 2.3.0 is archived with different files." },
    });
    expect(code).toBe(EXIT.usage);
    expect(stderr).toContain("never change");
    expect(stderr).toContain("Version 2.3.0 is archived with different files.");
  });

  it("asks for `cra all` first when the SBOM is not there, without calling the service", async () => {
    const dir = project({ sbom: false });
    const { code, stderr, requests } = await publish(
      dir,
      ["--to", "https://cra.example"],
      archived,
    );
    expect(code).toBe(EXIT.usage);
    expect(stderr).toContain("cra all");
    expect(requests).toHaveLength(0);
  });

  it("reports an unreachable or failing service with the network exit code", async () => {
    const dir = project();
    const { code } = await publish(dir, ["--to", "https://cra.example"], {
      status: 503,
      body: { title: "Unavailable" },
    });
    expect(code).toBe(EXIT.network);
  });
});
