# Changelog

All notable changes to this package are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Pre-npm bulletproofing track. Will ship as the first published version
(v0.1.2 or, if API surface settles, v0.2.0).

### Added

- GitHub Actions CI matrix on Node 20 and 22 covering typecheck, lint,
  test, build for every PR and push to `main`.
- `SECURITY.md` pointing reporters at GitHub Security Advisories.
- `CODEOWNERS` so the platform owner is the auto-reviewer.
- oxlint config matching the platform-ecosystem convention; `pnpm lint`
  wired into CI.
- `nbf` (not-before) claim enforcement on verify.
- Clock-skew tolerance on `exp` and `nbf` via `options.paseto.clockSkew`
  (default 60s, configurable, set 0 for strict).
- Web Crypto Ed25519 runtime probe at plugin `init`. Fails loud naming
  Node 20+, Cloudflare Workers, and Bun >= 1.1.0 as verified runtimes,
  instead of failing cryptically on the first sign call.
- `verifyPasetoWithReason` export returning a structured discriminated
  union: `{ ok: true, payload }` or `{ ok: false, error: { kind, message } }`
  with `kind` in `expired | not_yet_valid | invalid_signature | wrong_issuer | wrong_audience | missing_kid | unknown_kid | malformed`.
- Per-instance async mutex on key creation. Concurrent sign calls
  racing past a rotation boundary collapse to a single creation per
  rotation interval within an instance.
- Property tests via `fast-check` covering the verifier's negative path
  (random byte garbage, garbage payloads, unknown kids, non-kid footer
  shapes -- all return null, none throw).
- Concurrency tests pin: GET `/paseto-keys` never writes; 20 concurrent
  first-touch GETs share the seeded key; 20 concurrent post-rotation
  signs produce exactly one new key.
- Tagged-release publish workflow with SLSA provenance via OIDC.
- Dependabot config for weekly npm + GitHub Actions updates.

### Changed

- `/paseto-keys` GET no longer creates the first key lazily. The init
  hook seeds it at server-startup. Installations using `keys.remoteUrl`
  or `options.adapter` skip the seed and seed out-of-band.
- `paseto-ts` `verify` is now called with `validatePayload: false`. The
  plugin owns claim validation end-to-end (necessary so clock-skew
  tolerance is not blocked by paseto-ts's built-in checks).
- `createPasetoKey` takes a narrow `{ adapter, secretConfig }` shape
  instead of a full `GenericEndpointContext`, so it runs from both
  request handlers and the init hook.
- `adapter.createKey` arg order flipped to `(key, requestCtx?)`.
  Request context is only required for the user-adapter override path.

## [0.1.1] -- 2026-05-21

### Changed

- Package scope renamed: `@rafters-studio/better-auth-paseto` ->
  `@rafters/better-auth-paseto`. Aligns with the rest of the `@rafters/`
  ecosystem (`ledger`, `mail-cloudflare`, `better-auth-resend`). Pre-npm,
  no deprecation alias.
- `/sign-paseto` now requires an authenticated session.
  `sub`/`iss`/`aud`/`iat`/`exp` always sourced from session and plugin
  options; caller-supplied values for those keys are stripped before
  signing. Supplementary application claims (`role`, `tier`, etc.) pass
  through. The `overrideOptions` body field is removed.
- `/verify-paseto` no longer accepts a caller-supplied `issuer`
  override. Claim expectations come from plugin options.
- `getLatestKey` adapter call pushes `sortBy` + `limit: 1` down instead
  of loading all keys and sorting in JS.
- README peer-dep version corrected (`>= 1.6.0`).

### Added

- "Differences from the JWT plugin" section explaining the deliberate
  POST-endpoint deviations.
- `paseto-ts` quirks documented under "Calling `signPaseto` directly".
- Standalone-verification context requirement called out.

## [0.1.0] -- 2026-05-21

### Added

- Initial draft. PASETO v4.public plugin for better-auth, shape-port
  of the upstream JWT plugin with Ed25519 swapped in for JOSE.
- `/paseto-keys`, `/token`, `/sign-paseto`, `/verify-paseto` endpoints.
- `set-auth-paseto` response header on `/get-session`.
- Key rotation via `keys.rotationInterval` + `keys.gracePeriod`.
- Encrypted-at-rest private keys (toggleable via
  `keys.disablePrivateKeyEncryption`).
- JWKS-shaped public-key endpoint for cross-language interop.

[Unreleased]: https://github.com/rafters-studio/better-auth-paseto/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/rafters-studio/better-auth-paseto/releases/tag/v0.1.1
[0.1.0]: https://github.com/rafters-studio/better-auth-paseto/releases/tag/v0.1.0
