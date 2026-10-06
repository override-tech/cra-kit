import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/sbom/discover";
import { parsePnpmLock } from "../src/sbom/lockfiles/pnpm";
import { parseRequirement } from "../src/sbom/lockfiles/python";
import type { Inventory } from "../src/sbom/model";
import { makePurl, parsePurl } from "../src/sbom/purl";

const fixture = (name: string) => join(import.meta.dirname, "fixtures", name);
const inventory = (name: string, includeDev = false, paths = ["."]) =>
  buildInventory(fixture(name), paths, includeDev);
/** "name@version scope", sorted, for compact assertions. */
const listed = (inv: Inventory) =>
  inv.components.map((c) => `${c.name}@${c.version} ${c.scope}`).sort();
const byName = (inv: Inventory, name: string, version?: string) =>
  inv.components.find((c) => c.name === name && (version === undefined || c.version === version));

describe("npm package-lock.json", () => {
  it("lists production packages with nested versions, scopes and licenses", () => {
    const inv = inventory("npm");
    expect(listed(inv)).toEqual([
      "@scope/util@2.1.0 required",
      "debug@2.6.9 required",
      "express@4.18.2 required",
      "fsevents@2.3.3 optional",
      "left-pad@1.3.0 required",
      "ms@2.0.0 required",
      "ms@2.1.3 required",
      "qs@6.11.0 required",
    ]);
    expect(byName(inv, "@scope/util")?.purl).toBe("pkg:npm/%40scope/util@2.1.0");
    expect(byName(inv, "@scope/util")?.dependsOn).toEqual(["pkg:npm/ms@2.1.3"]);
    expect(byName(inv, "express")?.dependsOn).toEqual(["pkg:npm/debug@2.6.9", "pkg:npm/qs@6.11.0"]);
    expect(byName(inv, "qs")?.licenses).toEqual(["BSD-3-Clause"]);
    expect(byName(inv, "express")?.hashes[0]?.alg).toBe("SHA-512");
    expect(byName(inv, "express")?.hashes[0]?.content).toMatch(/^[0-9a-f]{128}$/);
  });

  it("treats workspace dependencies as direct and keeps dev packages only on request", () => {
    expect(inventory("npm").direct).toEqual([
      "pkg:npm/%40scope/util@2.1.0",
      "pkg:npm/express@4.18.2",
      "pkg:npm/fsevents@2.3.3",
      "pkg:npm/left-pad@1.3.0",
    ]);
    const withDev = inventory("npm", true);
    expect(byName(withDev, "vitest")?.scope).toBe("excluded");
    expect(byName(withDev, "tinyspy")?.scope).toBe("excluded");
  });

  it("rejects lockfileVersion 1 with a way forward", () => {
    expect(() => inventory("npm-v1")).toThrow(/lockfileVersion 1 is not supported.*npm 7/);
  });
});

describe("pnpm-lock.yaml v9", () => {
  it("follows importers, links between workspace packages, peers and aliases", () => {
    const inv = inventory("pnpm");
    expect(listed(inv)).toEqual([
      "fsevents@2.3.3 optional",
      "js-tokens@4.0.0 required",
      "lodash@4.17.20 required",
      "loose-envify@1.4.0 required",
      "react-dom@18.2.0 required",
      "react@18.2.0 required",
      "scheduler@0.23.2 required",
      "string-width@4.2.3 required",
    ]);
    expect(byName(inv, "react-dom")?.dependsOn).toEqual([
      "pkg:npm/loose-envify@1.4.0",
      "pkg:npm/react@18.2.0",
      "pkg:npm/scheduler@0.23.2",
    ]);
  });

  it("scopes to one importer of a monorepo lockfile", () => {
    const text = readFileSync(join(fixture("pnpm"), "pnpm-lock.yaml"), "utf8");
    const result = parsePnpmLock(text, {
      file: "pnpm-lock.yaml",
      dir: fixture("pnpm"),
      includeDev: false,
      importer: "packages/core",
    });
    expect(result.components.map((c) => c.purl)).toEqual(["pkg:npm/lodash@4.17.20"]);
    expect(() =>
      parsePnpmLock(text, {
        file: "pnpm-lock.yaml",
        dir: fixture("pnpm"),
        includeDev: false,
        importer: "nope",
      }),
    ).toThrow(/no importer/);
  });

  it("marks development-only packages excluded when asked to include them", () => {
    const inv = inventory("pnpm", true);
    expect(byName(inv, "typescript")?.scope).toBe("excluded");
    expect(byName(inv, "tinyspy")?.scope).toBe("excluded");
    expect(byName(inv, "react")?.scope).toBe("required");
  });
});

describe("yarn.lock", () => {
  it("parses classic lockfiles, resolving aliases and optional dependencies", () => {
    const inv = inventory("yarn-classic");
    expect(listed(inv)).toEqual([
      "ansi-styles@3.2.1 required",
      "chalk@2.4.2 required",
      "color-convert@1.9.3 required",
      "color-name@1.1.3 required",
      "escape-string-regexp@1.0.5 required",
      "fsevents@2.3.3 optional",
      "has-flag@3.0.0 required",
      "string-width@4.2.3 required",
      "supports-color@5.5.0 required",
    ]);
    const chalk = byName(inv, "chalk");
    expect(chalk?.hashes.map((h) => h.alg)).toEqual(["SHA-1", "SHA-512"]);
    expect(chalk?.hashes[0]?.content).toBe("cd42541677a54333cf541a49108c1432b44c9424");
  });

  it("parses berry lockfiles with workspaces and patched packages", () => {
    const inv = inventory("yarn-berry");
    expect(listed(inv)).toEqual(["lodash@4.17.21 required", "ms@2.1.3 required"]);
    expect(byName(inventory("yarn-berry", true), "typescript")?.scope).toBe("excluded");
  });

  it("finds the workspace lockfile above a monorepo package and scopes to it", () => {
    const inv = inventory("yarn-berry", false, ["packages/lib"]);
    expect(listed(inv)).toEqual(["ms@2.1.3 required"]);
    expect(inv.lockfiles).toEqual(["yarn.lock#packages/lib"]);
  });
});

describe("Python", () => {
  it("reads requirements.txt with includes, hashes, extras and markers", () => {
    const inv = inventory("python-requirements");
    expect(inv.components.map((c) => c.purl)).toEqual([
      "pkg:pypi/django@4.2.7",
      "pkg:pypi/jinja2@3.1.2",
      "pkg:pypi/markupsafe@2.1.3",
      "pkg:pypi/pyyaml@6.0.1",
      "pkg:pypi/requests",
    ]);
    expect(inv.warnings.some((w) => w.includes("requests is not pinned"))).toBe(true);
    expect(inv.warnings.some((w) => w.includes("editable requirement skipped"))).toBe(true);
    expect(inv.components.every((c) => !c.graphKnown)).toBe(true);
  });

  it("parses PEP 508 requirement lines", () => {
    expect(parseRequirement("requests[socks]==2.31.0 ; python_version > '3.7'")).toEqual({
      name: "requests",
      version: "2.31.0",
    });
    expect(parseRequirement("Django>=4,<5")).toEqual({ name: "Django", version: null });
  });

  it("reads poetry.lock, classifying through pyproject.toml when groups are absent", () => {
    const inv = inventory("poetry");
    expect(listed(inv)).toEqual([
      "certifi@2024.2.2 required",
      "charset-normalizer@3.3.2 required",
      "idna@3.6 required",
      "requests@2.31.0 required",
      "rich@13.7.1 optional",
      "urllib3@2.2.1 required",
    ]);
    expect(inv.direct).toEqual(["pkg:pypi/requests@2.31.0", "pkg:pypi/rich@13.7.1"]);
  });
});

describe("Go", () => {
  it("reads go.mod requires, applying replace directives", () => {
    const inv = inventory("go");
    expect(inv.components.map((c) => c.purl)).toEqual([
      "pkg:golang/github.com/BurntSushi/toml@v1.3.2%2Bincompatible",
      "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
      "pkg:golang/github.com/new/thing@v1.2.0",
      "pkg:golang/github.com/stretchr/testify@v1.8.4",
      "pkg:golang/golang.org/x/net@v0.17.0",
    ]);
    expect(inv.direct).not.toContain("pkg:golang/golang.org/x/net@v0.17.0");
    expect(inv.direct).toContain("pkg:golang/github.com/new/thing@v1.2.0");
    expect(
      inv.warnings.some((w) => w.includes("example.com/local is replaced by the local directory")),
    ).toBe(true);
  });

  it("falls back to go.sum for modules older than Go 1.17", () => {
    const inv = inventory("go-legacy");
    expect(inv.components.map((c) => c.purl)).toEqual([
      "pkg:golang/github.com/a/b@v1.0.0",
      "pkg:golang/github.com/c/d@v0.2.0",
    ]);
  });
});

describe("Cargo.lock", () => {
  it("excludes dev-dependencies of workspace members and keeps checksums", () => {
    const inv = inventory("cargo");
    expect(listed(inv)).toEqual([
      "log@0.4.21 required",
      "serde@1.0.197 required",
      "serde_derive@1.0.197 required",
    ]);
    expect(byName(inv, "serde")?.hashes).toEqual([
      {
        alg: "SHA-256",
        content: "3fb1c873e1b9b056a4dc4c0c198b24c3ffa059243875552b2bd0933b1aee4ce2",
      },
    ]);
    expect(byName(inv, "serde")?.dependsOn).toEqual(["pkg:cargo/serde_derive@1.0.197"]);
    expect(inv.direct).toEqual(["pkg:cargo/log@0.4.21", "pkg:cargo/serde@1.0.197"]);
    expect(byName(inventory("cargo", true), "fastrand")?.scope).toBe("excluded");
  });
});

describe("composer.lock", () => {
  it("separates packages from packages-dev and normalises v-prefixed versions", () => {
    const inv = inventory("composer");
    expect(inv.components.map((c) => c.purl)).toEqual([
      "pkg:composer/monolog/monolog@3.5.0",
      "pkg:composer/psr/log@3.0.0",
      "pkg:composer/symfony/polyfill-mbstring@1.29.0",
    ]);
    expect(byName(inv, "psr/log")?.hashes).toEqual([
      { alg: "SHA-1", content: "fe5ea303b0887d5caefd3d431c3e61ad47037001" },
    ]);
    expect(byName(inv, "monolog/monolog")?.dependsOn).toEqual(["pkg:composer/psr/log@3.0.0"]);
    expect(inv.direct).toEqual([
      "pkg:composer/monolog/monolog@3.5.0",
      "pkg:composer/symfony/polyfill-mbstring@1.29.0",
    ]);
  });
});

describe("discovery", () => {
  it("reports configured paths without a lockfile", () => {
    expect(() => buildInventory(fixture("."), ["cargo/crates"], false)).toThrow(
      /no lockfile found/,
    );
    expect(() => buildInventory(fixture("."), ["missing"], false)).toThrow(/does not exist/);
  });
});

describe("purl", () => {
  it("round-trips namespaced names and encodes versions", () => {
    const purl = makePurl("npm", "@types/node", "20.0.0+build.1");
    expect(purl).toBe("pkg:npm/%40types/node@20.0.0%2Bbuild.1");
    expect(parsePurl(purl)).toEqual({
      type: "npm",
      name: "@types/node",
      version: "20.0.0+build.1",
    });
    expect(makePurl("pypi", "Foo_Bar.baz", "1.0")).toBe("pkg:pypi/foo-bar-baz@1.0");
    expect(parsePurl("pkg:golang/github.com/a/b@v1.0.0?type=module#sub")).toEqual({
      type: "golang",
      name: "github.com/a/b",
      version: "v1.0.0",
    });
  });
});
