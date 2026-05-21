# hono-app

Complete runnable Hono app demonstrating `@rafters-studio/better-auth-paseto` end-to-end. Uses better-auth's in-memory adapter so it spins up with zero infra.

## Run

```sh
pnpm install
pnpm dev
# -> Listening on http://localhost:3000
```

Two endpoints to know:

- `/api/auth/*` — better-auth's mount point. The PASETO plugin contributes `/api/auth/paseto-keys`, `/api/auth/token`, `/api/auth/sign-paseto`, `/api/auth/verify-paseto`, and the `set-auth-paseto` response header on `/api/auth/get-session`.
- `/me` — a protected example route that reads the session and echoes the user.

## Walkthrough

### 1. Inspect the public key set

```sh
curl http://localhost:3000/api/auth/paseto-keys
```

Response (JWKS-shaped):

```json
{
  "keys": [
    {
      "kid": "<uuid>",
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "use": "sig",
      "x": "<base64url-public-key>"
    }
  ]
}
```

The keypair is created on first read. Subsequent calls return the same key until rotation.

### 2. Sign up a user

```sh
curl -X POST http://localhost:3000/api/auth/sign-up/email \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "alice@example.com",
    "password": "correct-horse-battery-staple",
    "name": "Alice"
  }'
```

The response carries a session cookie (saved to `cookies.txt`).

### 3. Hit /get-session and grab the PASETO from the response header

```sh
curl -v http://localhost:3000/api/auth/get-session -b cookies.txt 2>&1 | grep -i set-auth-paseto
```

Output:

```
< set-auth-paseto: v4.public.<base64url-payload>.<base64url-footer>
```

That's the session-derived PASETO. Subsequent backend services can verify it against `/paseto-keys` without ever touching better-auth.

### 4. Mint an arbitrary token via /sign-paseto

```sh
curl -X POST http://localhost:3000/api/auth/sign-paseto \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "sub": "agent-7",
      "aud": "http://localhost:3000",
      "scope": "read:notes"
    }
  }'
```

Response:

```json
{ "token": "v4.public.<payload>.<footer>" }
```

### 5. Verify a token

```sh
TOKEN="v4.public...."
curl -X POST http://localhost:3000/api/auth/verify-paseto \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$TOKEN\"}"
```

Response (valid):

```json
{
  "payload": {
    "sub": "agent-7",
    "iss": "http://localhost:3000",
    "aud": "http://localhost:3000",
    "iat": "2026-...",
    "exp": "2026-...",
    "scope": "read:notes"
  }
}
```

Response (invalid / tampered / expired / wrong issuer):

```json
{ "payload": null }
```

### 6. Hit the protected /me

```sh
curl http://localhost:3000/me -b cookies.txt
```

Response:

```json
{
  "user": { "id": "<uuid>", "email": "alice@example.com", "name": "Alice", ... }
}
```

## What this example does NOT do

- **No persistence.** The in-memory adapter forgets everything on restart. For a real app, swap in better-auth's Prisma, Drizzle, or MongoDB adapter.
- **No JWT bridge.** If you need to accept legacy JWTs during migration, that lives in a separate package.
- **No real auth provider.** Email/password is enabled here because it works without external config. For social logins, JWT IdPs, or passkeys, add the appropriate better-auth plugin alongside `paseto()`.
- **No production secrets.** `BETTER_AUTH_SECRET` is hardcoded as a dev placeholder. Set it via env in any real deployment.
