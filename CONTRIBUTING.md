# Contributing

## Setup

```sh
pnpm install
pnpm test       # 55 tests across 6 files
pnpm typecheck
pnpm lint
pnpm build
```

Node 20+ required. Web Crypto Ed25519 is the runtime floor. The plugin probes for it at `init` and throws if unavailable.

## Branches and PRs

- Default branch: `main`.
- All changes ship through a PR. Branch protection requires CI green and at least one reviewer approval. Admin bypass is off; even repo owners go through review.
- `legion pr create` opens the PR and gates on a clean `legion-simplify` run on `HEAD`.

## Releasing

Tag-driven release via `.github/workflows/release.yml`. Matches the rest of the `@rafters/` ecosystem (`ledger`, `mail`, `astro-data`, `astro-meta`) -- publish goes through **npm trusted publishing via OIDC**, no `NPM_TOKEN` involved.

```sh
# 1. Bump the version + commit
npm version patch -m "v%s"

# 2. Push the tag
git push --tags
```

The workflow runs typecheck / lint / test / build, then `npm publish --access=public --provenance`. The OIDC exchange happens on the `--provenance` flag and attaches a SLSA attestation to the published package. A GitHub Release is created from auto-generated notes against the tag.

### Operator setup (one-time, before the first release)

Configure npm trusted publishing for `@rafters/better-auth-paseto`:

1. Publish v0.1.x once manually under a maintainer account so the package exists on npm.
2. Go to <https://www.npmjs.com/package/@rafters/better-auth-paseto/access>.
3. Trusted publishers -> **Add Trusted Publisher** -> GitHub Actions.
4. Repository: `rafters-studio/better-auth-paseto`. Workflow filename: `release.yml`. Environment: leave blank.

After that the workflow handles every subsequent release via OIDC. **No `NPM_TOKEN` secret on the repo is needed or wanted** -- setting one (or `NODE_AUTH_TOKEN` in the publish step env) short-circuits OIDC and the publish fails with the wrong auth method.

The matching footguns are baked into a comment in the workflow header. Read it before editing `release.yml`.

### Versioning

Manual `npm version` bump for now. If release cadence picks up we can adopt [changesets](https://github.com/changesets/changesets) -- `mail` already uses it for the multi-package case.

`CHANGELOG.md` is updated by hand with each release. Keep entries in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. The GitHub Release uses `--generate-notes` so the auto-generated text catches anything CHANGELOG missed.

## Security reports

See [SECURITY.md](./SECURITY.md). Do not file security issues publicly.
