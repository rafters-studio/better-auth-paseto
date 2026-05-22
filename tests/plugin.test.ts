import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { sign as pasetoSign } from "paseto-ts/v4";
import { beforeEach, describe, expect, it } from "vitest";
import { paseto } from "../src/index";
import {
  base64UrlDecode,
  generateExportedKeyPair,
  jwkToPasetoSecretKey,
} from "../src/utils";
import {
  BASE_URL,
  freshDb,
  makeAuth,
  makeAuthWithSeededKeys,
  signUpAndGetCookie,
} from "./helpers";

/**
 * Spin up a real better-auth instance with the paseto plugin against an
 * in-memory adapter. These tests exercise the full plugin contract:
 * endpoints, response shapes, the set-auth-paseto header, key generation
 * on first call, and the verifyPaseto wrapper's claim enforcement.
 */

const ED25519_SIG_BYTES = 64;

/**
 * Decode the PASETO v4.public payload without verification. Format:
 *   v4.public.<base64url(payload_json_bytes || ed25519_signature)>[.<footer>]
 * The signature is the trailing 64 bytes of the decoded segment 2; payload
 * JSON is the prefix. Used only to inspect what the server stamped into a
 * token without round-tripping through /verify-paseto.
 */
function decodePasetoPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts[0] !== "v4" || parts[1] !== "public") {
    throw new Error(`not a v4.public token: ${token.slice(0, 16)}...`);
  }
  const bytes = base64UrlDecode(parts[2]!);
  const payloadBytes = bytes.slice(0, bytes.length - ED25519_SIG_BYTES);
  return JSON.parse(new TextDecoder().decode(payloadBytes));
}

describe("paseto plugin: /paseto-keys", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("returns a JWKS-shaped key set", async () => {
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

  it("filters keys whose expiresAt + gracePeriod has passed", async () => {
    const { publicWebKey: livePub, privateWebKey: livePriv } =
      await generateExportedKeyPair();
    const { publicWebKey: deadPub, privateWebKey: deadPriv } =
      await generateExportedKeyPair();
    const longAgo = new Date(Date.now() - 1000 * 60 * 60 * 24 * 365);

    const localAuth = makeAuthWithSeededKeys(
      [
        { id: "live-key", publicKey: livePub, privateKey: livePriv },
        {
          id: "dead-key",
          publicKey: deadPub,
          privateKey: deadPriv,
          createdAt: longAgo,
          expiresAt: longAgo,
        },
      ],
      { keys: { disablePrivateKeyEncryption: true, gracePeriod: 60 * 60 * 24 * 7 } },
    );

    const res = await localAuth.handler(
      new Request(`${BASE_URL}/api/auth/paseto-keys`),
    );
    expect(res.status).toBe(200);
    const { keys } = await res.json();
    const ids = keys.map((k: { kid: string }) => k.kid);
    expect(ids).toContain("live-key");
    expect(ids).not.toContain("dead-key");
  });
});

describe("paseto plugin: /sign-paseto auth + claim hardening", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("rejects unauthenticated requests", async () => {
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload: { role: "anything" } }),
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it("rejects malformed body (missing payload)", async () => {
    const cookie = await signUpAndGetCookie(auth);
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({}),
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it("signs supplementary claims and stamps sub from the session", async () => {
    const cookie = await signUpAndGetCookie(auth);
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ payload: { role: "admin", tier: "pro" } }),
      }),
    );
    expect(res.status).toBe(200);
    const { token } = await res.json();
    expect(typeof token).toBe("string");
    expect(token.startsWith("v4.public.")).toBe(true);

    const payload = decodePasetoPayload(token);
    expect(payload.role).toBe("admin");
    expect(payload.tier).toBe("pro");
    expect(typeof payload.sub).toBe("string");
    expect(payload.iss).toBe("https://test.example.com");
    expect(payload.aud).toBe("https://test.example.com");
  });

  it("ignores caller-supplied sub/iss/aud/iat/exp on /sign-paseto", async () => {
    const cookie = await signUpAndGetCookie(auth);
    const farFuture = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 10);
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({
          payload: {
            sub: "attacker-controlled",
            iss: "https://attacker.example.com",
            aud: "https://attacker.example.com",
            exp: farFuture.toISOString(),
            role: "admin",
          },
        }),
      }),
    );
    expect(res.status).toBe(200);
    const { token } = await res.json();
    const payload = decodePasetoPayload(token);
    expect(payload.sub).not.toBe("attacker-controlled");
    expect(payload.iss).toBe("https://test.example.com");
    expect(payload.aud).toBe("https://test.example.com");
    const expMs = new Date(payload.exp as string).getTime();
    const fifteenMinFromNow = Date.now() + 15 * 60 * 1000;
    expect(expMs).toBeLessThan(fifteenMinFromNow + 5_000);
    expect(payload.role).toBe("admin");
  });
});

describe("paseto plugin: /verify-paseto", () => {
  let auth: ReturnType<typeof makeAuth>;

  beforeEach(() => {
    auth = makeAuth();
  });

  it("rejects a malformed body", async () => {
    const res = await auth.handler(
      new Request("https://test.example.com/api/auth/verify-paseto", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("verifies a session-derived token round-trip", async () => {
    const cookie = await signUpAndGetCookie(auth, "bob@example.com");
    const tokenRes = await auth.handler(
      new Request("https://test.example.com/api/auth/token", {
        headers: { cookie },
      }),
    );
    const { token } = await tokenRes.json();

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

  it("returns null for a tampered token body", async () => {
    const cookie = await signUpAndGetCookie(auth, "carol@example.com");
    const signRes = await auth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ payload: { role: "user" } }),
      }),
    );
    const { token } = await signRes.json();
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
    const { payload } = await verifyRes.json();
    expect(payload).toBeNull();
  });

  it("returns null when the footer kid is rebased to a different known key", async () => {
    // Sign a token with key A, then rewrite the footer to claim key B.
    // Verify must fail: the signature was produced by A's secret, but the
    // verifier loads B's public key based on the (untrusted) footer claim.
    const { publicWebKey: pubA, privateWebKey: privA } =
      await generateExportedKeyPair();
    const { publicWebKey: pubB, privateWebKey: privB } =
      await generateExportedKeyPair();

    const localAuth = makeAuthWithSeededKeys([
      { id: "key-a", publicKey: pubA, privateKey: privA },
      { id: "key-b", publicKey: pubB, privateKey: privB },
    ]);

    const secretA = jwkToPasetoSecretKey(privA as any);
    const tokenSignedByA = pasetoSign(
      secretA,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      { footer: { kid: "key-a" } },
    );

    const parts = tokenSignedByA.split(".");
    const rebasedFooter = btoa(JSON.stringify({ kid: "key-b" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const rebased = [parts[0], parts[1], parts[2], rebasedFooter].join(".");

    const verifyRes = await localAuth.handler(
      new Request(`${BASE_URL}/api/auth/verify-paseto`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: rebased }),
      }),
    );
    expect(verifyRes.status).toBe(200);
    const { payload } = await verifyRes.json();
    expect(payload).toBeNull();
  });

  it("returns null for an expired token", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const localAuth = makeAuthWithSeededKeys([
      { id: "test-kid-1", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);

    const secretPaserk = jwkToPasetoSecretKey(privateWebKey as any);
    const expiredToken = pasetoSign(
      secretPaserk,
      {
        sub: "user-7",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date(Date.now() - 120_000).toISOString(),
        exp: new Date(Date.now() - 60_000).toISOString(),
      },
      // validatePayload:false skips claim validation, but addIat/addExp
      // default true would otherwise overwrite our explicit past dates --
      // disable both so the token is genuinely expired on the wire.
      {
        footer: { kid: "test-kid-1" },
        validatePayload: false,
        addIat: false,
        addExp: false,
      },
    );

    const verifyRes = await localAuth.handler(
      new Request(`${BASE_URL}/api/auth/verify-paseto`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: expiredToken }),
      }),
    );
    const { payload } = await verifyRes.json();
    expect(payload).toBeNull();
  });

  it("returns null when iss does not match plugin options", async () => {
    // /sign-paseto no longer lets a caller override iss, so produce a
    // wrong-issuer token directly against a seeded key.
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const localAuth = makeAuthWithSeededKeys([
      { id: "kid-iss-test", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const secret = jwkToPasetoSecretKey(privateWebKey as any);
    const wrongIssuerToken = pasetoSign(
      secret,
      {
        sub: "u",
        iss: "https://wrong-issuer.example.com",
        aud: BASE_URL,
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      { footer: { kid: "kid-iss-test" } },
    );

    const res = await localAuth.handler(
      new Request(`${BASE_URL}/api/auth/verify-paseto`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: wrongIssuerToken }),
      }),
    );
    const { payload } = await res.json();
    expect(payload).toBeNull();
  });
});

describe("paseto plugin: rotation", () => {
  it("mints a fresh key on sign once the latest key has expired", async () => {
    const db: Record<string, any[]> = freshDb();
    const localAuth = betterAuth({
      baseURL: "https://test.example.com",
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(db),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          keys: {
            rotationInterval: 1,
            gracePeriod: 60 * 60,
          },
          paseto: {
            issuer: "https://test.example.com",
            audience: "https://test.example.com",
          },
        }),
      ],
    });

    const signUpRes = await localAuth.handler(
      new Request("https://test.example.com/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "rot@example.com",
          password: "correct-horse-battery-staple",
          name: "Rot",
        }),
      }),
    );
    const cookie = signUpRes.headers.get("set-cookie")!;

    const first = await localAuth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ payload: { phase: "first" } }),
      }),
    );
    const { token: tokenA } = await first.json();
    expect(tokenA.startsWith("v4.public.")).toBe(true);

    expect(db.paseto_keys.length).toBe(1);
    const firstKid = db.paseto_keys[0]!.id;

    await new Promise((r) => setTimeout(r, 1_100));

    const second = await localAuth.handler(
      new Request("https://test.example.com/api/auth/sign-paseto", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ payload: { phase: "second" } }),
      }),
    );
    const { token: tokenB } = await second.json();
    expect(tokenB.startsWith("v4.public.")).toBe(true);
    expect(db.paseto_keys.length).toBe(2);

    const keysRes = await localAuth.handler(
      new Request("https://test.example.com/api/auth/paseto-keys"),
    );
    const { keys } = await keysRes.json();
    const ids = keys.map((k: { kid: string }) => k.kid);
    expect(ids).toContain(firstKid);
    expect(ids.length).toBe(2);
  });
});

describe("paseto plugin: session-derived header", () => {
  it("attaches a set-auth-paseto header to /get-session when a session exists", async () => {
    const auth = makeAuth();
    const cookie = await signUpAndGetCookie(auth);

    const sessionRes = await auth.handler(
      new Request("https://test.example.com/api/auth/get-session", {
        headers: { cookie },
      }),
    );
    expect(sessionRes.status).toBe(200);
    const token = sessionRes.headers.get("set-auth-paseto");
    expect(token).toBeTruthy();
    expect(token!.startsWith("v4.public.")).toBe(true);
  });

  it("suppresses the set-auth-paseto header when disableSettingHeader is true", async () => {
    const auth = makeAuth({ disableSettingHeader: true });
    const cookie = await signUpAndGetCookie(auth, "noheader@example.com");

    const sessionRes = await auth.handler(
      new Request("https://test.example.com/api/auth/get-session", {
        headers: { cookie },
      }),
    );
    expect(sessionRes.status).toBe(200);
    expect(sessionRes.headers.get("set-auth-paseto")).toBeNull();
  });
});
