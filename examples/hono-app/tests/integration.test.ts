import { verify as pasetoVerify } from "paseto-ts/v4";
import { describe, expect, it } from "vitest";
import { app } from "../src/app";

/**
 * End-to-end integration tests against the real Hono app. These exercise
 * surfaces the in-memory adapter tests in the parent package do not:
 *
 * - Hono's routing layer (the /api/auth/* mount)
 * - The full request/response shape from a consumer's perspective
 * - The workspace dep `@rafters/better-auth-paseto` resolving correctly
 *   through pnpm workspace + the package's exports field
 * - Cross-library verification: hand a token back to paseto-ts directly,
 *   using the public key fetched from /api/auth/paseto-keys
 *
 * Uses `app.fetch` directly -- same code path real Node consumers hit
 * through `@hono/node-server`, but no socket overhead per test.
 */

const ORIGIN = "http://localhost:3000";

async function fetchApp(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  return app.fetch(new Request(`${ORIGIN}${path}`, init));
}

async function signUp(email: string): Promise<string> {
  const res = await fetchApp("/api/auth/sign-up/email", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      password: "correct-horse-battery-staple",
      name: "Integration",
    }),
  });
  const cookie = res.headers.get("set-cookie");
  if (!cookie) {
    throw new Error(`sign-up returned ${res.status} without a cookie`);
  }
  return cookie;
}

/**
 * Decode an Ed25519 OKP JWK's `x` field to raw 32-byte public key, then
 * wrap it in the PASERK `k4.public.<base64url>` envelope that paseto-ts
 * accepts.
 */
function jwkToPasetoPublicKey(x: string): string {
  const pad = "=".repeat((4 - (x.length % 4)) % 4);
  const b64 = (x + pad).replace(/-/g, "+").replace(/_/g, "/");
  // Re-encode without padding for the PASERK envelope.
  const stripped = b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `k4.public.${stripped}`;
}

describe("hono integration: /", () => {
  it("returns the health-check string", async () => {
    const res = await fetchApp("/");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("better-auth-paseto example Hono app");
  });
});

describe("hono integration: /api/auth/* mount", () => {
  it("GET /api/auth/paseto-keys returns a JWKS-shaped response with at least one key", async () => {
    const res = await fetchApp("/api/auth/paseto-keys");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
    const k = body.keys[0];
    expect(k.kty).toBe("OKP");
    expect(k.crv).toBe("Ed25519");
    expect(k.alg).toBe("EdDSA");
    expect(typeof k.kid).toBe("string");
    expect(typeof k.x).toBe("string");
  });

  it("rejects /api/auth/sign-paseto without a session", async () => {
    const res = await fetchApp("/api/auth/sign-paseto", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload: { role: "anything" } }),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});

describe("hono integration: full sign-up -> token -> verify round-trip", () => {
  it("issues and verifies a session-derived PASETO via HTTP", async () => {
    const cookie = await signUp("roundtrip@example.com");

    const tokenRes = await fetchApp("/api/auth/token", {
      headers: { cookie },
    });
    expect(tokenRes.status).toBe(200);
    const { token } = await tokenRes.json();
    expect(typeof token).toBe("string");
    expect(token.startsWith("v4.public.")).toBe(true);

    const verifyRes = await fetchApp("/api/auth/verify-paseto", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(verifyRes.status).toBe(200);
    const { payload } = await verifyRes.json();
    expect(payload).not.toBeNull();
    expect(typeof payload.sub).toBe("string");
  });

  it("attaches set-auth-paseto to /api/auth/get-session", async () => {
    const cookie = await signUp("header@example.com");
    const sessionRes = await fetchApp("/api/auth/get-session", {
      headers: { cookie },
    });
    expect(sessionRes.status).toBe(200);
    const header = sessionRes.headers.get("set-auth-paseto");
    expect(header).toBeTruthy();
    expect(header!.startsWith("v4.public.")).toBe(true);
  });
});

describe("hono integration: /me protected route", () => {
  it("returns 401 without a session cookie", async () => {
    const res = await fetchApp("/me");
    expect(res.status).toBe(401);
  });

  it("returns the user object with a valid session cookie", async () => {
    const cookie = await signUp("protected@example.com");
    const res = await fetchApp("/me", { headers: { cookie } });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user.email).toBe("protected@example.com");
  });
});

describe("hono integration: cross-library JWKS verification", () => {
  it("a token from /api/auth/token verifies against /api/auth/paseto-keys using paseto-ts directly", async () => {
    // This is the load-bearing interop test. The README sells the
    // JWKS-shaped /paseto-keys endpoint as the path for cross-language
    // verifiers (Rust for smugglr, etc). Prove the same path works
    // in-process: fetch the public key, hand it to paseto-ts, verify.
    const cookie = await signUp("interop@example.com");
    const tokenRes = await fetchApp("/api/auth/token", {
      headers: { cookie },
    });
    const { token } = await tokenRes.json();

    const keysRes = await fetchApp("/api/auth/paseto-keys");
    const { keys } = await keysRes.json();

    // The footer carries the kid; for this test we trust the single
    // returned key. A real cross-language verifier would parse the
    // footer to pick the right one.
    const k = keys[0];
    const publicKey = jwkToPasetoPublicKey(k.x);

    // Use validatePayload: false so paseto-ts does only signature
    // verification; the test asserts the JWKS path produces a key that
    // verifies the signature -- claim handling lives in the plugin.
    const result = pasetoVerify(publicKey, token, { validatePayload: false });
    expect(result.payload.sub).toBeTruthy();
    expect(result.payload.iss).toBeTruthy();
  });
});
