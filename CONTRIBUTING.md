# Contributing

Bug reports, fixes and new lockfile formats are welcome. Security problems go through
[SECURITY.md](SECURITY.md), never a public issue.

## Before you start

Open an issue first for anything larger than a bug fix, so we can agree on the approach before you write it.
Changes to `src/rules/` (scope, product classes, conformity routes, support period, Art. 14 clocks) need the
article, annex or recital they implement in the pull request description: these rules are shared with the hosted
ReleaseKeep service.

## Development

Node 22 or newer.

```sh
npm ci
npm run test:ci      # tests (no network)
npm run type-check
npm run lint         # Biome; `npm run lint:fix` formats and applies safe fixes
npm run build        # dist/cra.mjs
```

Tests must not touch the network. Put sample lockfiles under `test/fixtures/<ecosystem>/`.

## Pull requests

- Branch from `main`; `main` only changes through pull requests.
- CI must pass: lint, type-check, tests and build on Node 22 and 24, the action run against
  `test/fixtures/action`, and the workflow linters (actionlint, zizmor) when you touch `.github/` or `action.yml`.
- Pull requests are squash-merged and the title becomes the commit message on `main`: write it as one plain
  sentence that says what changes.
- Add or update tests for every behaviour change, and update `README.md` when a command, option or output changes.
- Pin any new GitHub Action to a full commit SHA with the version in a comment, e.g.
  `actions/checkout@<sha> # v4.4.0`. The repository rejects unpinned actions.

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
