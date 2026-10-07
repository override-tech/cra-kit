# cra - Cyber Resilience Act records for installed and distributed software

[![ci](https://github.com/override-tech/releasekeep/actions/workflows/ci.yml/badge.svg)](https://github.com/override-tech/releasekeep/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@override-tech/releasekeep)](https://www.npmjs.com/package/@override-tech/releasekeep)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Free and open source, from [ReleaseKeep](https://releasekeep.com). Not sure the CRA applies to your product?
Take the [scope test](https://releasekeep.com/scope) or read the [guides](https://releasekeep.com/guides).

`cra` keeps the paperwork of the EU Cyber Resilience Act (Regulation (EU) 2024/2847) next to your code.
Run it on every release tag and it regenerates, into `docs/compliance/`:

- a **scope verdict** with the product class (Annex III/IV), the conformity assessment route and every
  obligation with its article and the date it applies;
- a **CycloneDX 1.6 SBOM** built from your lockfiles (or by [Syft](https://github.com/anchore/syft) when it is
  installed);
- a **vulnerability scan** of that SBOM against [OSV.dev](https://osv.dev), cross-referenced with the
  [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog;
- **document templates**: technical documentation (Annex VII), risk assessment (Art. 13(2)-(4)), EU declaration
  of conformity (Annex V), vulnerability handling and CVD policy (Annex I Part II), `security.txt` (RFC 9116),
  support-period statement (Art. 13(8), (9), (19)), user information checklist (Annex II) and an Art. 14
  reporting runbook.

Commit the directory and the git history becomes the audit trail: every release shows exactly what changed in
the SBOM, the findings and the documents.

It is built for small vendors of software that users install or receive: self-hosted servers, desktop and
mobile apps, plugins, paid libraries, firmware. Pure SaaS is outside the CRA (Recital 12).

## What the documents are, and are not

- They are **templates and evidence** that the manufacturer completes, reviews and signs. `cra` never declares
  conformity on your behalf; the declaration of conformity it writes is an unsigned draft.
- The scope verdict is **triage with article references, not legal advice**.
- The SBOM and the scan cover third-party dependencies. They say nothing about your own code; the risk
  assessment is where you account for that.
- Every place where only you know the answer is marked `TODO(vendor)`. `grep -rn "TODO(vendor)" docs/compliance`
  lists them and `index.md` counts them per document.

## Install

Node 22 or newer:

```sh
npx @override-tech/releasekeep --help                 # run without installing
npm install --save-dev @override-tech/releasekeep   # or pin it in the project; the command is `cra`
```

Each [GitHub release](https://github.com/override-tech/releasekeep/releases) also carries `cra.mjs`, a single file with
no dependencies: download it and run `node cra.mjs`. To build it yourself: `npm ci && npm run build`, which
writes `dist/cra.mjs`.

## Quick start

```sh
cra init          # writes a commented cra.yml
$EDITOR cra.yml   # replace the TODO values, check every answer marked REVIEW
cra scope         # verdict, class, route, obligations
cra all           # SBOM + scan + documents into docs/compliance/
```

Add `.cra-cache/` (the vulnerability feed cache) to `.gitignore`.

## Commands

| Command | What it does |
| --- | --- |
| `cra init [--force]` | Writes a commented `cra.yml` template (never overwrites without `--force`). |
| `cra scope` | Prints the scope verdict, product class, conformity route, obligations with articles and dates, and notes on legacy products (Art. 69). |
| `cra sbom [--out <file>\|-]` | Writes the CycloneDX 1.6 SBOM to `<output.dir>/sbom.cdx.json`, another file, or stdout (`-`). |
| `cra scan [--sbom <file>]` | Scans a freshly generated SBOM, or an existing CycloneDX JSON file, and prints the findings. Exit code per `scan.failOn`. |
| `cra docs` | Writes all records into `output.dir`. |
| `cra all [--summary <file>] [--outputs <file>]` | `scope` + `sbom` + `scan` + `docs` in one run, for CI. `--summary` appends a Markdown summary (use `$GITHUB_STEP_SUMMARY`), `--outputs` appends `key=value` lines (use `$GITHUB_OUTPUT`). Exit code per `scan.failOn`. |
| `cra publish [--to <url>] [--artifact <file>]...` | Archives this release with the hosted [ReleaseKeep](https://releasekeep.com) service: every file `cra all` wrote to `output.dir` (top level) plus each `--artifact` as `artifacts/<name>`, under the product version. Needs the product's upload token in `RELEASEKEEP_TOKEN`; the address is `https://releasekeep.com` unless `--to` or `RELEASEKEEP_URL` names another. An archived version never changes: publishing different files under it fails with exit code 1. |
| `cra clock --kind <k> --aware <ISO> [--fixed <ISO>] [--notified <ISO>] [--warned <ISO>]` | Art. 14 deadlines and their state for an actively exploited vulnerability (`exploited_vulnerability`: 24 h, 72 h, 14 days after the fix) or a severe incident (`severe_incident`: 24 h, 72 h, one month after the notification). `--warned` marks the early warning as sent. |

Global options:

| Option | Meaning |
| --- | --- |
| `--config <path>` | `cra.yml` to use (default `cra.yml` in the project directory). |
| `--cwd <dir>` | Project directory (default: the current directory). |
| `--version <v>` | Product version for this run. Without a command, `--version` prints the cra version. |
| `--fail-on <level>` | Override `scan.failOn`. |
| `--offline` | No network: use cached OSV and KEV data only. `scope` never touches the network, and `docs` succeeds without it (the scan is then marked as not performed). |
| `--now <ISO time>` | Run as if it were this moment (reproducible output; also pins the release date). `SOURCE_DATE_EPOCH` works the same way. |
| `--json` | Machine-readable output on stdout. |
| `--quiet` | Errors only. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Usage or configuration error (bad flag, invalid `cra.yml`, unreadable lockfile, unknown product version). |
| 2 | Findings at or above `scan.failOn`. |
| 3 | OSV or the CISA KEV feed was unreachable while not running with `--offline` (`scan`, `all`). `all` still writes the records, with the scan marked as not performed. For `publish`: the ReleaseKeep service was unreachable or failed. |

## Configuration (cra.yml)

```yaml
product:
  name: Acme Backup
  version: "2.3.0"                # optional: else --version, else the git tag (v2.3.0 -> 2.3.0)
  manufacturer:
    name: Acme Software sp. z o.o.
    address: ul. Prosta 1, 00-001 Warszawa, Poland
    email: legal@acme.example
    website: https://acme.example # optional
  distribution: self_hosted_server
  coreFunction: none_of_the_above
  monetisation: [subscription_or_licence]
  availableInEu: true             # default true
  isFoss: false
  isOpenSourceSteward: false      # default false
  publicTechnicalDocs: false      # default false
  placedOnMarketAt: 2025-03       # optional, YYYY-MM or YYYY-MM-DD
  substantialModificationAfterApplication: false  # default false
  intendedPurpose: Encrypted backups of company file servers, run on customer premises.
  supportEndsAt: 2032-12          # YYYY-MM (last day of the month) or YYYY-MM-DD
  expectedUseYears: 3             # optional, only to justify a period under five years
  securityContact:
    email: security@acme.example
    url: https://acme.example/security                 # optional, CVD policy page (https)
    pgpKey: https://acme.example/pgp.asc               # optional, https URL or 40-hex fingerprint
  languages: [en, pl]             # Annex II user information, security.txt Preferred-Languages

sbom:
  paths: ["."]                    # directories or lockfiles, relative to the project
  includeDev: false               # list dev-only dependencies with scope "excluded"
  generator: auto                 # auto | syft | builtin

scan:
  failOn: kev                     # kev | critical | high | none

output:
  dir: docs/compliance
```

| Field | Values and effect |
| --- | --- |
| `distribution` | `desktop_app`, `mobile_app`, `browser_extension`, `self_hosted_server`, `plugin_or_extension`, `library_or_package`, `firmware_or_device`, `saas_only`. `saas_only` is out of scope (Recital 12). |
| `coreFunction` | `none_of_the_above` or a category of Annex III (class I or II) or Annex IV, as described in Implementing Regulation (EU) 2025/2392. Classify by the product's core function. `cra init` lists every value. |
| `monetisation` | Any of `price`, `paid_support_beyond_costs`, `subscription_or_licence`, `ads_or_data_monetisation`, `donations_beyond_costs`, or `none` alone. Without monetisation the product is not supplied in the course of a commercial activity (Recital 15, 18). |
| `isOpenSourceSteward` | A legal person that sustains FOSS intended for commercial use (Art. 3(14)): light-touch regime of Art. 24 when it does not monetise. |
| `publicTechnicalDocs` | FOSS in Annex III with public technical documentation may use module A (Art. 32(5)). |
| `placedOnMarketAt` | Products placed before 11 December 2027 only owe Art. 14 reporting until substantially modified (Art. 69(2)-(3)). |
| `supportEndsAt` | Checked against the five-year minimum of Art. 13(8), measured from `placedOnMarketAt` or, until that is set, from the release date. |
| `scan.failOn` | `kev`: fail only on findings in CISA KEV. `critical` / `high`: fail on findings of that severity or worse. A KEV-listed finding fails every level except `none`. |

Validation errors point at the line and suggest the key or value you probably meant:

```text
cra.yml is not valid:
  - cra.yml:8:17 product.distribution "self_hosted" is not one of: desktop_app, ... (did you mean "self_hosted_server"?)
  - cra.yml:12:11 product.isFOSS unknown key (did you mean "isFoss"?)
```

Values still containing `TODO` are accepted with a warning, so the pipeline runs while you fill them in.

## Generated files

| File | Contents |
| --- | --- |
| `index.md` | Product, version, scope, SBOM SHA-256, scan result, links to everything, open vendor items, generation time and cra version. |
| `technical-documentation.md` | Annex VII sections 1-8, pre-filled from `cra.yml`, the SBOM and the scan. |
| `risk-assessment.md` | Art. 13(2)-(4) context, then each requirement of Annex I Part I(2)(a)-(m) with an applicability and status block; the overview table is rebuilt from your answers. |
| `declaration-of-conformity.md` | Annex V items 1-8 as an unsigned draft, plus the Annex VI simplified declaration. |
| `vulnerability-handling.md` | CVD policy and each requirement of Annex I Part II(1)-(8). |
| `support-period.md` | The Art. 13(19) statement (month and year), the Art. 13(8) check, the Art. 13(9) availability dates and the Art. 13(13) retention date, computed with the rules in `src/rules/`. |
| `user-information.md` | Annex II items 1-9 with what `cra.yml` already answers. |
| `reporting-runbook.md` | Art. 14 steps, deadlines and contents, the ENISA Single Reporting Platform, what to collect, and a worked example; flags KEV findings from the latest scan. |
| `security.txt` | RFC 9116: `Contact`, `Expires` (the first of the current month, one year on), `Encryption`, `Policy`, `Preferred-Languages`. Serve it at `/.well-known/security.txt`. |
| `sbom.cdx.json` | CycloneDX 1.6 JSON. |
| `scan.json` | Findings with severity, CVSS vector, KEV flag, fixed versions and advisory links. |

### Your sections survive regeneration

Text between `<!-- cra:vendor <id> -->` and `<!-- cra:end <id> -->` belongs to you: `cra` carries it over every
time it regenerates the file. Everything outside those markers is rewritten. Files in the output directory that
`cra` does not generate are never touched.

### Diffs show real changes

Output is sorted and stable. Only `index.md` and the SBOM metadata (`timestamp`, and the `serialNumber`, which is
derived from the content and the timestamp) carry the generation time. `security.txt` changes once a month. The
release date used for Art. 13(9) is the date of the `HEAD` commit, so regenerating a tag gives the same documents.
Set `SOURCE_DATE_EPOCH` (or `--now`) to make the SBOM byte-identical as well.

## SBOM

With `generator: auto`, `cra` runs `syft dir:<path> -o cyclonedx-json@1.6` when Syft is on `PATH` and rewrites
the result to name your product as `metadata.component`. Otherwise, and always with `generator: builtin`, it reads
the lockfiles in each `sbom.paths` entry:

| Ecosystem | Files | Dependency graph | Dev dependencies told apart by |
| --- | --- | --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` (lockfileVersion 2 and 3) | yes | reachability from `package.json` roots |
| pnpm | `pnpm-lock.yaml` (lockfileVersion 9) | yes | importers |
| Yarn | `yarn.lock` (classic v1 and berry) | yes | workspace `package.json` files |
| Python | `poetry.lock`, `requirements*.txt` (with `-r` includes) | poetry: yes | lock groups or `pyproject.toml` |
| Go | `go.mod` (+ `go.sum` before Go 1.17) | direct only | - |
| Rust | `Cargo.lock` | yes | member `Cargo.toml` `[dev-dependencies]` |
| PHP | `composer.lock` | yes | `packages` / `packages-dev` |

Components carry a package URL, version, scope (`required`, `optional`, or `excluded` for dev dependencies when
`includeDev` is on), hashes from the lockfile and licenses where the lockfile records them. Pointing `sbom.paths`
at a package inside a JavaScript monorepo uses the workspace lockfile above it, limited to that package.
Unpinned `requirements.txt` entries are listed without a version and reported, since they cannot be scanned.

Syft and the built-in reader can disagree (Syft also catalogs vendored and test files); pick one with
`sbom.generator` so that local runs and CI produce the same SBOM.

## Vulnerability scan

- Package URLs are sent to `https://api.osv.dev/v1/querybatch` in batches of 500, following pagination; each
  advisory is then fetched from `/v1/vulns/{id}`.
- Advisories for the same issue (GHSA and PYSEC, say) are merged through their aliases. Their CVE ids are looked
  up in the CISA KEV feed.
- Severity comes from the CVSS v3 vector when present, else the database's rating (CVSS v4-only records), else
  CVSS v2. Fixed versions come from the advisory's ranges for that package.
- Feeds are cached in `.cra-cache/` for six hours. `--offline` uses the cache whatever its age; components never
  checked are reported as unchecked rather than clean.
- Every request has a 30-second timeout and up to three attempts. `CRA_OSV_API` and `CRA_KEV_URL` point at mirrors.

## CI

### GitHub Action

```yaml
# .github/workflows/cra.yml
name: CRA records
on:
  push:
    tags: ["v*"]

permissions:
  contents: write   # only needed with commit: true

jobs:
  cra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: override-tech/releasekeep@v0
        with:
          config: cra.yml
          fail-on: kev
          commit: true
```

The action runs `cra all`, writes the scope verdict and a table of findings to the job summary, uploads the
output directory as the `cra-compliance` artifact and, with `commit: true` on a tag build that passed, commits the
records to the default branch as `docs(compliance): CRA records for <tag>`. It fails the job with the `cra` exit
code. Release tags (`v0`, `v0.1.0`, ...) carry the bundled CLI; any other ref (a branch or a commit) is built
from source first, which needs npm registry access.

| Input | Default | Meaning |
| --- | --- | --- |
| `config` | `cra.yml` | Path to `cra.yml`, relative to `working-directory`. |
| `fail-on` | from `cra.yml` | `kev`, `critical`, `high` or `none`. |
| `commit` | `false` | Commit the records back on tag builds. |
| `node-version` | `24` | Node.js version. |
| `working-directory` | `.` | Project directory. |
| `artifact-name` | `cra-compliance` | Name of the uploaded artifact. |
| `upload-token` | | The product's ReleaseKeep upload token; pass `${{ secrets.RELEASEKEEP_TOKEN }}`. With it, tag builds that passed archive the release. |
| `releasekeep-url` | `https://releasekeep.com` | Another ReleaseKeep instance. |
| `artifacts` | | Release files to archive with the records, one path per line. |

Outputs: `output-dir`, `verdict`, `findings`, `kev`, `exit-code`.

### Hosted archive

The CRA requires every released version, its SBOM and its declaration of conformity to stay available for ten
years (Art. 13(9), 13(13)), and a current security contact and support period to be published. With an upload
token from [ReleaseKeep](https://releasekeep.com), the action archives each tagged release and keeps the product's public
security page, `security.txt` and CSAF advisories current:

```yaml
      - uses: override-tech/releasekeep@v0
        with:
          fail-on: kev
          upload-token: ${{ secrets.RELEASEKEEP_TOKEN }}
          artifacts: |
            dist/app_linux_amd64.tar.gz
```

To use Syft in CI, add `anchore/sbom-action/download-syft` before the action and set `sbom.generator: syft`.

### Other CI systems

```sh
npx @override-tech/releasekeep all --summary summary.md
```

Exit code 2 fails the build on findings over the threshold; archive or commit `docs/compliance/`.

## Development

```sh
npm ci
npm run test:ci      # tests (no network)
npm run type-check
npm run lint
npm run build        # dist/cra.mjs
```

The legal rules (scope, product classes, conformity routes, support period, Art. 14 clocks) are in `src/rules/`.
They are shared with the hosted ReleaseKeep service, so a fix there reaches both.

Releases: bump `version` in `package.json` on `main`, then push the tag `v<version>`. The release workflow checks
and builds it, publishes the npm package and moves the `v<major>` action tag.

Issues and pull requests are welcome. Report a security problem in this tool privately, as described in
[SECURITY.md](SECURITY.md), not in an issue.

## License

[Apache License 2.0](LICENSE). The generated documents are yours.
