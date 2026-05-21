# @rafters-studio/better-auth-paseto

PASETO v4.public plugin for [better-auth](https://better-auth.com). Drop-in shape-compatible replacement for better-auth's built-in JWT plugin.

## Why

JWT carries known design problems: algorithm-confusion attacks via the `alg` header, no encryption by default, no replay protection, no standardized key rotation, and a sprawling JOSE spec surface that punishes anyone trying to use it correctly. ([Why JWT is dead, long live PASETO.](https://sean.silvius.me/posts/security-jwt-is-dead/))

PASETO (Platform-Agnostic Security Tokens) closes the holes. v4.public is the asymmetric-signed variant:

- **Fixed at Ed25519.** No `alg` header to manipulate. The algorithm is bound to the version (`v4.public`).
- **Authenticated footer for key rotation.** `kid` lives in the footer, which is authenticated by the signature -- a tampered `kid` routes to a wrong key, signature verification fails.
- **Small spec surface.** One construction, one set of registered claims, no plug-in algorithms.

## Install

```sh
pnpm add @rafters-studio/better-auth-paseto
```

Peer dependency: `better-auth >= 1.0.0`.

## Usage

```ts
import { betterAuth } from "better-auth";
import { paseto } from "@rafters-studio/better-auth-paseto";

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

| Endpoint           | Method | Purpose                                                        |
| ------------------ | ------ | -------------------------------------------------------------- |
| `/paseto-keys`     | GET    | Public-key set, JWKS-shaped for interop                        |
| `/token`           | GET    | Mint a PASETO derived from the active session                  |
| `/sign-paseto`     | POST   | Sign an arbitrary claims payload                               |
| `/verify-paseto`   | POST   | Verify a token and return its payload (or null)                |

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

## Migration from the JWT plugin

The plugin shape is intentionally identical: same endpoints, same hooks, same options layout under different names. To migrate:

1. Install this plugin alongside the JWT plugin.
2. Switch your verification path to read `set-auth-paseto` instead of `set-auth-jwt`.
3. Switch your verifiers to fetch `/paseto-keys` and use a PASETO library.
4. Remove the JWT plugin once your last issued JWT has expired.

The two plugins coexist cleanly -- they use separate tables (`jwks` vs `paseto_keys`) and separate response headers.

## Storage shape

The plugin stores Ed25519 keypairs as JWK JSON (`{kty:"OKP", crv:"Ed25519", x, d}`). Two reasons:

1. The `/paseto-keys` endpoint can emit JWKS-shaped JSON directly -- public keys are interoperable with any JWK-aware consumer (just decode the `x` field for raw PASETO use).
2. The encrypted-at-rest path matches the JWT plugin's pattern, so the better-auth secret-driven `symmetricEncrypt` works without change.

PASETO sign/verify use raw byte keys; the plugin extracts those from the JWK at call time. The cost is negligible (microseconds).

## What this plugin is NOT

- **Not a PASETO v4.local provider.** Symmetric session encryption is a separate concern; v0.1 is v4.public only. Adding v4.local is a clean extension if needed.
- **Not a JWT bridge.** If you need to accept legacy JWTs alongside PASETO during migration, layer a separate token-exchange endpoint that verifies the JWT and mints a PASETO. Keeping that out of this plugin keeps the dependency surface clean (no JOSE).
- **Not an agent-auth protocol.** [Agent Auth Protocol](https://agentauthprotocol.com) is the right place for per-agent identity, capability-scoped tokens, and autonomous-agent flows. PASETO is the underlying token format; AAP is the semantic layer for agent traffic.

## Status

v0.1 draft. Tested against `paseto-ts` v1.6. Dogfooded in [smugglr](https://github.com/rafters-studio/smugglr) and [fence](https://github.com/rafters-studio/) (private). Issues and PRs welcome.

## License

MIT.
