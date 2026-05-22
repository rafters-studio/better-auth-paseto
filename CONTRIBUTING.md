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

Tagged-release auto-publish wires up via `.github/workflows/release.yml`.

```sh
# 1. Bump the version + commit
npm version patch -m "v%s"

# 2. Push the tag
git push --tags
```

The workflow runs typecheck / lint / test / build, then `pnpm publish --access public --provenance --no-git-checks`. Provenance attaches a SLSA attestation to the npm package.

### Operator setup (one-time)

- `NPM_TOKEN` repository secret: a granular npm access token scoped to publish `@rafters/better-auth-paseto` only. Rotate yearly.
- Token type: **Granular Access Token** (not Classic). Read-only on `@rafters` org metadata, read-write on this package's publish action.
- Permissions for the workflow: `contents: read`, `id-token: write` (already in the workflow file -- enables OIDC for provenance).

### Versioning

Manual `npm version` bump until release cadence picks up. If we adopt automation, prefer [changesets](https://github.com/changesets/changesets) -- it works cleanly with pnpm workspaces and produces good changelogs.

`CHANGELOG.md` is updated by hand with each release. Keep entries in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Security reports

See [SECURITY.md](./SECURITY.md). Do not file security issues publicly.
