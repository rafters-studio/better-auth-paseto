# Security Policy

`@rafters/better-auth-paseto` is a token-handling library. Vulnerabilities here can affect every deployment that uses it. We treat reports seriously and we reply.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

This will change as the package reaches 1.0. Until then, only the latest 0.1.x release receives security fixes.

## Reporting a vulnerability

**Do not open a public issue.** Public issues describing an unfixed vulnerability are an attack vector themselves — they tell anyone watching the repo exactly where to look.

Use **GitHub Security Advisories** instead:

1. Go to the [Security tab](https://github.com/rafters-studio/better-auth-paseto/security).
2. Click **Report a vulnerability**.
3. Fill in the form. You can attach a private fork if you have a candidate patch.

This routes directly to the maintainers without leaving a public trail.

## What to expect

| Stage              | Target window         |
| ------------------ | --------------------- |
| Acknowledgement    | 5 business days       |
| Initial assessment | 10 business days      |
| Fix + release      | 30 days for high/crit |

We'll keep you updated through the advisory thread. When the fix ships, you're credited in the advisory unless you ask otherwise.

## Scope

In scope:

- Cryptographic correctness (signature verification, key derivation, claim handling)
- Authentication and session boundaries on the plugin's endpoints
- Side-channel leakage via error messages, timing, or logs
- Supply-chain concerns specific to this package (publishing pipeline, dependency exposure)

Out of scope:

- Vulnerabilities in `paseto-ts` itself — file those upstream at [auth70/paseto-ts](https://github.com/auth70/paseto-ts).
- Vulnerabilities in `better-auth` itself — file those at [better-auth/better-auth](https://github.com/better-auth/better-auth).
- Application-layer concerns (rate limiting, replay protection, authorization decisions) — those are the consumer's responsibility.

If you're not sure which side of the line a finding falls on, file the advisory here and we'll route it.
