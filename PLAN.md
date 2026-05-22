# Plan

The single document that walks the v0.1.x bulletproofing track end to end. Each phase below has a matching GitHub issue with detailed tasks and acceptance criteria; this file is the table of contents and the order of operations.

The goal of the track: take the package from "merged, tested, works" to "ready for npm with the surface area a security library at v1 needs."

## Status snapshot

| Version  | Status     | Notes                                                                 |
| -------- | ---------- | --------------------------------------------------------------------- |
| v0.1.0   | tagged     | Initial draft. Verbatim shape port of better-auth's JWT plugin.       |
| v0.1.1   | tagged     | Scope rename to `@rafters/`, endpoint defaults tightened. Closes #1. |
| v0.1.2+  | in flight  | Phases A-D below.                                                     |
| v0.2.0   | future     | v4.local support if there is demand. Not on the critical path.       |
| v1.0.0   | future     | Cut after Phases A-D land, after at least one real consumer ships.   |

## v0.1.x bulletproofing track

Four independent phases. A is a hard prereq for B/C/D because it sets up CI; once A is green every other PR is gated by it. B/C/D themselves do not depend on each other and can land in any order or in parallel.

### Phase A -- shop-fitting (#3)

Make the repo look and behave like a published security library before anyone could responsibly disclose against it.

- GitHub Actions on PR and `main`: `pnpm test`, `pnpm typecheck`, `pnpm build`, Node 20.x and 22.x matrix
- `SECURITY.md` pointing to GitHub Security Advisories as the disclosure channel
- `CODEOWNERS` so the platform agent is the auto-reviewer
- oxlint config matching the platform monorepo standard, `pnpm lint` wired into CI
- README badges (CI status, license, semver)

Estimated effort: ~1h. Lowest risk in the track. Start here.

### Phase B -- spec parity + verifier hardening (#4)

Close the claim-handling and runtime-safety gaps that should be there before the package goes public.

- `nbf` (not-before) enforcement on verify -- symmetric to the existing `exp` check
- Clock skew tolerance for `exp` and `nbf`, default 60s, configurable
- Web Crypto Ed25519 runtime probe at plugin init -- fail loud at boot, not cryptically on first sign
- Structured `PasetoVerifyError` discriminated union for server-side consumers who want to log rejection reasons without leaking them in the HTTP response
- Tests for: secret-rotation decrypt failure, malformed tokens, `nbf` future/past, clock skew symmetry, missing Web Crypto

Estimated effort: ~2h. Depends on A for CI only.

### Phase C -- concurrency + production hygiene (#5)

Take the racy first-touch and rotation paths from "matches upstream" to "actually safe under load."

- Move lazy-init out of the `GET /paseto-keys` handler into a better-auth `init` hook -- reads stop mutating
- Per-plugin-instance async mutex around `createPasetoKey` with re-check-on-entry to collapse concurrent first-touches and post-rotation creates within a single Worker / Node instance
- Document the cross-instance limitation honestly; point consumers needing stricter guarantees at D1 `INSERT OR IGNORE` adapters or external coordination
- Property tests (`fast-check`) for the verifier path: random byte garbage never throws, always resolves to a null payload
- Concurrency tests for rotation: 50 simultaneous signs at the boundary produce at most one fresh key per interval

Estimated effort: ~2h. Depends on A for CI only.

### Phase D -- release pipeline (#6)

Make `git tag && git push --tags` the only step needed to ship a new version.

- `.github/workflows/release.yml` triggered on `v*` tags: tests + build + `pnpm publish --access public --provenance`
- Operator-side: `NPM_TOKEN` secret with a granular access token scoped to `@rafters/better-auth-paseto` only
- Dependabot config: weekly updates for `paseto-ts`, `better-auth`, `@better-auth/core`, Vitest, TypeScript
- `CHANGELOG.md` seeded with v0.1.0 and v0.1.1 entries
- Decision deferred: changesets vs manual versioning -- pick when the first real consumer lands

Estimated effort: ~30m. Depends on A for the base CI workflow.

## After v0.1.x

Not on the critical path. Listed so the next agent does not file these as gaps when they look at the package.

- **v4.local provider.** Symmetric session encryption is a separate concern; v0.1 is v4.public only. Adding v4.local is a clean extension, do it if a consumer asks.
- **Client package.** `./client` is wired into `package.json` exports but unimplemented. Build it out when better-auth consumers need typed access to the endpoints from a browser bundle.
- **JWKS-aware migration tooling.** Tool that drops a `kty:"OKP", crv:"Ed25519"` JWK from the existing better-auth JWT plugin's `jwks` table directly into `paseto_keys`. Lowers the bar for the JWT-to-PASETO migration documented in the README.
- **Cross-language verifier examples.** README's "Differences from the JWT plugin" section leans on the `/paseto-keys` JWKS interop story. A worked example in Rust (for smugglr) and one more language would make that story load-bearing.
- **Agent-auth integration.** [Agent Auth Protocol](https://agentauthprotocol.com) layers semantic claims for autonomous agents. PASETO is the underlying token format; AAP is the semantic layer. If platform ever adopts AAP, this package is the token side of that integration.

## Ownership

Platform agent owns this repo. Track via `agent = "platform"` in legion's `watch.toml`. Cross-package coordination (when paseto interacts with `@rafters/ledger`, `@rafters/mail-cloudflare`, `@rafters/better-auth-resend`) goes through the platform bullpen, not this repo's issue tracker.
