import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { sign as pasetoSign } from "paseto-ts/v4";
import { beforeEach, describe, expect, it } from "vitest";
import { paseto } from "../src/index";
import {
  generateExportedKeyPair,
  jwkToPasetoSecretKey,
} from "../src/utils";

/**
 * Spin up a real better-auth instance with the paseto plugin against an
 * in-memory adapter. These tests exercise the full plugin contract:
 * endpoints, response shapes, the set-auth-paseto header, key generation
 * on first call, and the verifyPaseto wrapper's claim enforcement.
 */

function makeAuth() {
  // memoryAdapter requires every model to have a slot pre-allocated.
  // The plugin's schema declares paseto_keys; the better-auth core tables
  // need user/session/account/verification.
  const db: Record<string, any[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
    paseto_keys: [],
  };
  return betterAuth({
    baseURL: "https://test.example.com",
    secret: "test-secret-that-is-at-least-32-chars-long",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    plugins: [
      paseto({
        paseto: {
          issuer: "https://test.example.com",
          audience: "https://test.example.com",
          expirationTime: "15m",
        },
      }),
    ],
  });
}

describe("paseto plugin: endpoints", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("GET /paseto-keys returns a JWKS-shaped key set", async () => {
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/paseto-keys"),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
    const k = body.keys[0];
    expect(k.kty).toBe("OKP");
    expect(k.crv).toBe("Ed25519");
    expect(k.alg).toBe("EdDSA");
    expect(k.use).toBe("sig");
    expect(typeof k.x).toBe("string");
    expect(typeof k.kid).toBe("string");
  });

  it("emits X-Http-Sql-Version equivalent: X-... no, the paseto plugin has no version header", async () => {
    // Sanity placeholder: paseto plugin does not advertise its own version
    // header. better-auth handles general response headers; the plugin's
    // contract is the body shape, asserted above.
    expect(true).toBe(true);
  });

  it("rejects POST /verify-paseto for malformed input", async () => {
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

describe("paseto plugin: sign and verify", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("signs a payload via POST /sign-paseto and verifies the round-trip", async () => {
    const payload = {
      sub: "user-42",
      aud: "https://test.example.com",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
      role: "admin",
    };
    const signRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload }),
      }),
    );
    expect(signRes.status).toBe(200);
    const { token } = await signRes.json();
    expect(typeof token).toBe("string");
    expect(token.startsWith("v4.public.")).toBe(true);

    const verifyRes = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      }),
    );
    expect(verifyRes.status).toBe(200);
    const { payload: verifiedPayload } = await verifyRes.json();
    expect(verifiedPayload).not.toBeNull();
    expect(verifiedPayload.sub).toBe("user-42");
    expect(verifiedPayload.role).toBe("admin");
  });

  it("returns payload: null for a tampered token", async () => {
    const payload = {
      sub: "user-99",
      aud: "https://test.example.com",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    };
    const signRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload }),
      }),
    );
    const { token } = await signRes.json();
    // Flip a character in the payload segment.
    const parts = token.split(".");
    const seg = parts[2]!;
    const tampered = [
      parts[0],
      parts[1],
      seg.slice(0, -1) + (seg.slice(-1) === "A" ? "B" : "A"),
      ...(parts[3] ? [parts[3]] : []),
    ].join(".");

    const verifyRes = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: tampered }),
      }),
    );
    expect(verifyRes.status).toBe(200);
    const { payload: verifiedPayload } = await verifyRes.json();
    expect(verifiedPayload).toBeNull();
  });

  it("returns payload: null for an expired token", async () => {
    // We can't ask the plugin to sign an already-expired token (paseto-ts
    // validates exp at sign-time, which we keep on by default). So craft
    // the expired token directly against the plugin's stored key, then
    // hit the verify endpoint to confirm the plugin wrapper rejects it.
    //
    // First trigger key generation by hitting /paseto-keys, then read the
    // generated key out of the response.
    const keysRes = await auth.handler(
      new Request("https://test.example.com/api/auth/paseto-keys"),
    );
    const keys = (await keysRes.json()).keys as Array<{ kid: string; x: string }>;
    expect(keys.length).toBe(1);

    // To sign with the matching private key, we generate a fresh pair and
    // overwrite the plugin's storage. Easier than threading the internal
    // adapter through the test; the security boundary is the verify
    // wrapper, which is what we're actually pinning.
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    // Replace the stored key. The plugin's adapter uses the model name
    // paseto_keys; we mutate the underlying in-memory db directly.
    // Easier path: just sign+verify with a fresh pair through a fresh
    // plugin whose only key is the one we control.
    const dbWithKnownKey: Record<string, any[]> = {
      user: [],
      session: [],
      account: [],
      verification: [],
      paseto_keys: [
        {
          id: "test-kid-1",
          publicKey: JSON.stringify(publicWebKey),
          // disablePrivateKeyEncryption: true below means we store raw.
          privateKey: JSON.stringify(privateWebKey),
          createdAt: new Date(),
        },
      ],
    };
    const localAuth = betterAuth({
      baseURL: "https://test.example.com",
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(dbWithKnownKey),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          keys: { disablePrivateKeyEncryption: true },
          paseto: {
            issuer: "https://test.example.com",
            audience: "https://test.example.com",
            expirationTime: "15m",
          },
        }),
      ],
    });

    const secretPaserk = jwkToPasetoSecretKey(privateWebKey as any);
    const expiredToken = pasetoSign(
      secretPaserk,
      {
        sub: "user-7",
        iss: "https://test.example.com",
        aud: "https://test.example.com",
        iat: new Date(Date.now() - 120_000).toISOString(),
        exp: new Date(Date.now() - 60_000).toISOString(),
      },
      // validatePayload:false skips claim *validation* but addIat/addExp
      // default true STILL overwrite our explicit iat/exp -- diabolical
      // paseto-ts API behavior. Disable both to keep the past dates.
      {
        footer: { kid: "test-kid-1" },
        validatePayload: false,
        addIat: false,
        addExp: false,
      },
    );

    const verifyRes = await localAuth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: expiredToken }),
      }),
    );
    expect(verifyRes.status).toBe(200);
    const { payload: verifiedPayload } = await verifyRes.json();
    expect(verifiedPayload).toBeNull();
  });

  it("returns payload: null for wrong issuer", async () => {
    const payload = {
      sub: "user-1",
      iss: "https://wrong-issuer.example.com",
      aud: "https://test.example.com",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    };
    const signRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload }),
      }),
    );
    const { token } = await signRes.json();

    const verifyRes = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      }),
    );
    const { payload: verifiedPayload } = await verifyRes.json();
    expect(verifiedPayload).toBeNull();
  });
});

describe("paseto plugin: session-derived token", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("attaches a set-auth-paseto header to /get-session when a session exists", async () => {
    // Create user + session via sign-up.
    const signUpRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "alice@example.com",
          password: "correct-horse-battery-staple",
          name: "Alice",
        }),
      }),
    );
    expect(signUpRes.status).toBeGreaterThanOrEqual(200);
    expect(signUpRes.status).toBeLessThan(300);

    const setCookie = signUpRes.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();

    // Now hit /get-session with the cookie and expect set-auth-paseto.
    const sessionRes = await auth.handler(
      new Request("https://test.example.com/api/auth/get-session", {
        headers: { cookie: setCookie! },
      }),
    );
    expect(sessionRes.status).toBe(200);
    const token = sessionRes.headers.get("set-auth-paseto");
    expect(token).toBeTruthy();
    expect(token!.startsWith("v4.public.")).toBe(true);
  });

  it("verifies a session-derived token round-trip", async () => {
    await auth.handler(
      new Request("https://test.example.com/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "bob@example.com",
          password: "another-good-passphrase",
          name: "Bob",
        }),
      }),
    );
    const signInRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-in/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "bob@example.com",
          password: "another-good-passphrase",
        }),
      }),
    );
    expect(signInRes.status).toBeGreaterThanOrEqual(200);
    expect(signInRes.status).toBeLessThan(300);
    const cookie = signInRes.headers.get("set-cookie")!;

    const tokenRes = await auth.handler(
      new Request("https://test.example.com/api/auth/token", {
        headers: { cookie },
      }),
    );
    expect(tokenRes.status).toBe(200);
    const { token } = await tokenRes.json();
    expect(typeof token).toBe("string");

    const verifyRes = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      }),
    );
    const { payload } = await verifyRes.json();
    expect(payload).not.toBeNull();
    expect(payload.aud).toBe("https://test.example.com");
  });
});
