# @rafters/better-auth-paseto

[![CI](https://github.com/rafters-studio/better-auth-paseto/actions/workflows/ci.yml/badge.svg)](https://github.com/rafters-studio/better-auth-paseto/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

PASETO v4.public plugin for [better-auth](https://better-auth.com). Shape-compatible replacement for better-auth's built-in JWT plugin, with safer defaults on the two POST endpoints (see [Differences from the JWT plugin](#differences-from-the-jwt-plugin)).

## Why

JWT carries known design problems: algorithm-confusion attacks via the `alg` header, no encryption by default, no replay protection, no standardized key rotation, and a sprawling JOSE spec surface that punishes anyone trying to use it correctly. ([Why JWT is dead, long live PASETO.](https://sean.silvius.me/posts/security-jwt-is-dead/))

PASETO (Platform-Agnostic Security Tokens) closes the holes. v4.public is the asymmetric-signed variant:

- **Fixed at Ed25519.** No `alg` header to manipulate. The algorithm is bound to the version (`v4.public`).
- **Authenticated footer for key rotation.** `kid` lives in the footer, which is authenticated by the signature -- a tampered `kid` routes to a wrong key, signature verification fails.
- **Small spec surface.** One construction, one set of registered claims, no plug-in algorithms.

## Install

```sh
pnpm add @rafters/better-auth-paseto
```

Peer dependencies: `better-auth >= 1.6.0`, `@better-auth/core >= 1.6.0`.

## Usage

```ts
import { betterAuth } from "better-auth";
import { paseto } from "@rafters/better-auth-paseto";

export const auth = betterAuth({
  baseURL: "https://app.example.com",
  database: yourAdapter,
  plugins: [
    paseto({
      paseto: {
        issuer: "https://app.example.com",
        audience: "https://api.example.com",
        expirationTime: "15m",
      },
    }),
  ],
});
```

That registers four endpoints (paths are relative to better-auth's base):

| Endpoint         | Method | Auth     | Purpose                                                                                |
| ---------------- | ------ | -------- | -------------------------------------------------------------------------------------- |
| `/paseto-keys`   | GET    | public   | Public-key set, JWKS-shaped for interop                                                |
| `/token`         | GET    | session  | Mint a session-derived PASETO                                                          |
| `/sign-paseto`   | POST   | session  | Mint a session-derived PASETO with caller-supplied **supplementary** claims            |
| `/verify-paseto` | POST   | public   | Verify a token against the configured issuer/audience; return payload or null          |

And one response hook: `/get-session` responses gain a `set-auth-paseto` header carrying a session-derived token, mirroring the JWT plugin's `set-auth-jwt` behavior.

## Options

```ts
interface PasetoOptions {
  keys?: {
    remoteUrl?: string;            // verify against a remote /paseto-keys URL
    disablePrivateKeyEncryption?: boolean;  // default: false (keys encrypted at rest)
    rotationInterval?: number;     // seconds; rotate signing key every N seconds
    gracePeriod?: number;          // seconds; keep retired keys in /paseto-keys this long. Default: 30d
    keysPath?: string;             // default: "/paseto-keys"
  };
  paseto?: {
    issuer?: string;               // defaults to baseURL origin
    audience?: string | string[];  // defaults to baseURL origin
    expirationTime?: number | string | Date;  // e.g. "15m", "1h", "7d", or absolute
    clockSkew?: number;            // seconds; tolerance on exp/nbf checks. Default: 60
    definePayload?: (session) => Record<string, any>;  // shape the session-derived payload
    getSubject?: (session) => string;  // override sub claim (default: user.id)
    sign?: (payload) => Promise<string>;  // custom/remote signer (requires keys.remoteUrl)
  };
  disableSettingHeader?: boolean;  // skip the set-auth-paseto response header
  schema?: ...;                    // override the paseto_keys table mapping
  adapter?: ...;                   // bring your own key storage (KMS, secrets store)
}
```

## Key rotation

Set `keys.rotationInterval` to a number of seconds. The plugin marks each new key with an `expiresAt` matching that interval. When a key's expiry passes, the next sign call creates a fresh key and uses it; the old key remains in `/paseto-keys` for `gracePeriod` seconds so in-flight tokens still verify.

If you want to rotate manually instead, set no `rotationInterval` and call `createPasetoKey(ctx, options)` from your own code when you want a fresh key.

## Differences from the JWT plugin

The endpoint surface mirrors the JWT plugin so existing consumers can switch with minimal churn. The two POST endpoints deliberately deviate on defaults the JWT plugin inherited from a more permissive era:

### `/sign-paseto` is session-only and ignores security-relevant caller claims

The PASETO plugin requires an authenticated session on `/sign-paseto` and treats the request body's `payload` as **supplementary application-level claims only**. The security-relevant claims are always sourced from server state:

- `sub` from the session (via `paseto.getSubject` or `user.id`)
- `iss`, `aud`, `exp` from plugin options (or the `baseURL` default)
- `iat` from the current server time

If the caller puts `sub`, `iss`, `aud`, `iat`, or `exp` into `payload`, those values are stripped before signing. Custom claims like `role`, `tier`, `org`, etc. pass through.

The `overrideOptions` body field that exists on the JWT plugin's `/sign-jwt` is not implemented here. Signer options (issuer, expiry, signing key, etc.) are server configuration, not request input.

### `/verify-paseto` does not let the caller pick the issuer

Claim expectations (`iss`, `aud`) come from plugin options. A verifier endpoint that lets the caller pick what to expect cannot meaningfully enforce the iss check, so the request body field is omitted.

### Migration steps

1. Install this plugin alongside the JWT plugin.
2. Switch your verification path to read `set-auth-paseto` instead of `set-auth-jwt`.
3. Switch your verifiers to fetch `/paseto-keys` and use a PASETO library (preferred), or hit `/verify-paseto`.
4. If you were calling `/sign-jwt` with arbitrary `sub` values, refactor to use the session-derived `/token` endpoint or call `signPaseto` from server-side code (the helper is exported).
5. Remove the JWT plugin once your last issued JWT has expired.

The two plugins coexist cleanly -- they use separate tables (`jwks` vs `paseto_keys`) and separate response headers.

## Storage shape

The plugin stores Ed25519 keypairs as JWK JSON (`{kty:"OKP", crv:"Ed25519", x, d}`). Two reasons:

1. The `/paseto-keys` endpoint can emit JWKS-shaped JSON directly -- public keys are interoperable with any JWK-aware consumer (just decode the `x` field for raw PASETO use).
2. The encrypted-at-rest path matches the JWT plugin's pattern, so the better-auth secret-driven `symmetricEncrypt` works without change.

PASETO sign/verify use raw byte keys; the plugin extracts those from the JWK at call time. The cost is negligible (microseconds).

## Calling `signPaseto` directly

The `signPaseto` helper is exported for server-side code that wants to mint a token without going through the HTTP endpoint. A couple of `paseto-ts` quirks to know about if you build payloads yourself:

- `paseto-ts` defaults `addIat: true` and `addExp: true` on `sign`, which **overwrite** explicit `iat`/`exp` claims in your payload unless you also pass `{ addIat: false, addExp: false }`. The plugin's helper sets `iat` explicitly and lets `paseto-ts`'s `addExp` fill in `exp` from plugin options -- if you call `signPaseto` with your own `exp`, expect the library to overwrite it unless you opt out.
- `paseto-ts`'s `verify` does not enforce `exp` rejection by default; the plugin's `verifyPaseto` wrapper layers that check on top. If you call the raw library directly, do your own expiry enforcement.

## Structured verify errors

The HTTP `/verify-paseto` endpoint always returns `{ payload: null }` on failure -- the wire never leaks why a token was rejected. Server-side code that wants to log or branch on the reason should use `verifyPasetoWithReason`:

```ts
import { verifyPasetoWithReason } from "@rafters/better-auth-paseto";

const result = await verifyPasetoWithReason(token);
if (result.ok) {
  console.log("verified", result.payload);
} else {
  switch (result.error.kind) {
    case "expired":           /* renew */ break;
    case "not_yet_valid":     /* nbf in future */ break;
    case "invalid_signature": /* bad sig */ break;
    case "wrong_issuer":      /* iss mismatch */ break;
    case "wrong_audience":    /* aud mismatch */ break;
    case "missing_kid":       /* footer has no kid */ break;
    case "unknown_kid":       /* kid not in /paseto-keys */ break;
    case "malformed":         /* not parseable as v4.public */ break;
  }
}
```

Same context requirement as `verifyPaseto` -- both call `getCurrentAuthContext()` and require a better-auth request scope.

## Clock skew

`options.paseto.clockSkew` (seconds, default 60) applies symmetrically to `exp` and `nbf` during verification. A token whose `exp` is within `clockSkew` seconds in the past still verifies; a token whose `nbf` is within `clockSkew` seconds in the future still verifies. Set to `0` to disable tolerance.

Distributed deployments routinely see a few seconds of clock drift between signer and verifier. 60s is conservative for most setups; tighten or loosen to suit your monitoring story.

The plugin passes `validatePayload: false` to `paseto-ts`'s `verify` so its built-in claim checks do not run -- `paseto-ts` does not support skew and a future-`nbf` token with a 60s skew would otherwise be rejected by the library before the plugin's skew logic could run. The plugin owns iss/aud/exp/nbf validation end-to-end.

## Runtime requirement

The plugin probes Web Crypto Ed25519 once during better-auth's plugin `init` phase. Verified runtimes:

- Node 20+
- Cloudflare Workers
- Bun >= 1.1.0

Older or non-conforming runtimes raise a `BetterAuthError` at init naming the requirement, instead of failing cryptically on the first sign call.

## Standalone verification

The exported `verifyPaseto` and `verifyPasetoWithReason` helpers resolve the active better-auth context via `getCurrentAuthContext()` and only work inside a better-auth request scope. To verify tokens from outside better-auth (background jobs, other frameworks, cross-language services), fetch `/paseto-keys` and call a PASETO library directly -- the JWKS-shaped endpoint exists for exactly this case.

## What this plugin is NOT

- **Not a PASETO v4.local provider.** Symmetric session encryption is a separate concern; v0.1 is v4.public only. Adding v4.local is a clean extension if needed.
- **Not a JWT bridge.** If you need to accept legacy JWTs alongside PASETO during migration, layer a separate token-exchange endpoint that verifies the JWT and mints a PASETO. Keeping that out of this plugin keeps the dependency surface clean (no JOSE).
- **Not an agent-auth protocol.** [Agent Auth Protocol](https://agentauthprotocol.com) is the right place for per-agent identity, capability-scoped tokens, and autonomous-agent flows. PASETO is the underlying token format; AAP is the semantic layer for agent traffic.

## Status

v0.1 draft. Tested against `paseto-ts` v1.6. Maintained by the platform team at Rafters Studio. Issues and PRs welcome.

## License

MIT.
