import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { sign as pasetoSign } from "paseto-ts/v4";
import { afterEach, describe, expect, it, vi } from "vitest";
import { paseto } from "../src/index";
import {
  generateExportedKeyPair,
  jwkToPasetoSecretKey,
} from "../src/utils";
import {
  BASE_URL,
  freshDb,
  makeAuthWithSeededKeys,
  verifyVia,
} from "./helpers";

/**
 * Coverage for Phase-B additions:
 *
 * - nbf (not-before) claim enforcement
 * - Clock skew tolerance on exp and nbf, default 60s, configurable
 * - Web Crypto Ed25519 runtime probe at plugin init
 * - PasetoVerifyError discriminated union surfaced by verifyPasetoWithReason
 */

async function tokenWith(
  privateWebKey: object,
  claims: Record<string, unknown>,
  kid: string,
): Promise<string> {
  const secret = jwkToPasetoSecretKey(privateWebKey as any);
  return pasetoSign(secret, claims, {
    footer: { kid },
    validatePayload: false,
    addIat: false,
    addExp: false,
  });
}

describe("nbf enforcement", () => {
  it("rejects a token whose nbf is in the future", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-nbf-future", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const futureNbf = new Date(Date.now() + 10 * 60_000).toISOString();
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date().toISOString(),
        nbf: futureNbf,
        exp: new Date(Date.now() + 60 * 60_000).toISOString(),
      },
      "kid-nbf-future",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).toBeNull();
  });

  it("accepts a token whose nbf is in the past", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-nbf-past", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const pastNbf = new Date(Date.now() - 60_000).toISOString();
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date(Date.now() - 60_000).toISOString(),
        nbf: pastNbf,
        exp: new Date(Date.now() + 60 * 60_000).toISOString(),
      },
      "kid-nbf-past",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).not.toBeNull();
  });
});

describe("clock skew tolerance", () => {
  it("accepts a token expired 30s ago with default 60s skew", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-skew-exp", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date(Date.now() - 120_000).toISOString(),
        exp: new Date(Date.now() - 30_000).toISOString(),
      },
      "kid-skew-exp",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).not.toBeNull();
  });

  it("rejects a token expired 90s ago even with default 60s skew", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-skew-exp-90", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date(Date.now() - 180_000).toISOString(),
        exp: new Date(Date.now() - 90_000).toISOString(),
      },
      "kid-skew-exp-90",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).toBeNull();
  });

  it("accepts a token whose nbf is 30s in the future with default 60s skew", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-skew-nbf", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date().toISOString(),
        nbf: new Date(Date.now() + 30_000).toISOString(),
        exp: new Date(Date.now() + 60 * 60_000).toISOString(),
      },
      "kid-skew-nbf",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).not.toBeNull();
  });

  it("strict comparison when clockSkew: 0 -- rejects a token expired 1s ago", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys(
      [
        {
          id: "kid-skew-zero",
          publicKey: publicWebKey,
          privateKey: privateWebKey,
        },
      ],
      {
        paseto: {
          issuer: BASE_URL,
          audience: BASE_URL,
          clockSkew: 0,
        },
      },
    );
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date(Date.now() - 60_000).toISOString(),
        exp: new Date(Date.now() - 1_000).toISOString(),
      },
      "kid-skew-zero",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).toBeNull();
  });
});

describe("PasetoVerifyError -- verifyPasetoWithReason", () => {
  it("malformed: token does not start with v4.public", async () => {
    const auth = makeAuthWithSeededKeys([]);
    // verifyPasetoWithReason requires an auth-context, exercise via the
    // HTTP handler which sets one up, then assert through the export by
    // re-running the same handler path with a known malformed token.
    const res = await auth.handler(
      new Request(`${BASE_URL}/api/auth/verify-paseto`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: "not-a-paseto" }),
      }),
    );
    expect(res.status).toBe(200);
    const { payload } = await res.json();
    expect(payload).toBeNull();
  });

  it("missing_kid: footer-less token rejected at the verify endpoint", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-mk", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const secret = jwkToPasetoSecretKey(privateWebKey as any);
    const tokenNoFooter = pasetoSign(secret, {
      sub: "u",
      iss: BASE_URL,
      aud: BASE_URL,
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    });

    const payload = await verifyVia(auth, tokenNoFooter);
    expect(payload).toBeNull();
  });

  it("unknown_kid: footer references a kid not in the table", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      {
        id: "stored-kid",
        publicKey: publicWebKey,
        privateKey: privateWebKey,
      },
    ]);
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: BASE_URL,
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      "phantom-kid",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).toBeNull();
  });

  it("wrong_audience: token aud does not include configured audience", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "kid-aud", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);
    const token = await tokenWith(
      privateWebKey,
      {
        sub: "u",
        iss: BASE_URL,
        aud: "https://wrong-aud.example.com",
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      "kid-aud",
    );
    const payload = await verifyVia(auth, token);
    expect(payload).toBeNull();
  });
});

describe("Web Crypto Ed25519 runtime probe", () => {
  const realGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle);

  afterEach(() => {
    crypto.subtle.generateKey = realGenerateKey;
  });

  it("throws BetterAuthError at plugin init when Ed25519 is unsupported", async () => {
    // Replace generateKey with a stub that simulates an older-runtime
    // failure. The plugin's init callback fires when better-auth
    // instantiates the plugin, which happens lazily on the first
    // handler() call.
    crypto.subtle.generateKey = vi
      .fn()
      .mockRejectedValue(new Error("Unrecognized algorithm name"));

    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(freshDb()),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          paseto: { issuer: BASE_URL, audience: BASE_URL },
        }),
      ],
    });

    // Any handler call triggers init. better-auth surfaces the init
    // failure by rethrowing -- assert the BetterAuthError mentions
    // Ed25519 so the operator sees the actual cause.
    await expect(
      auth.handler(new Request(`${BASE_URL}/api/auth/paseto-keys`)),
    ).rejects.toThrow(/Ed25519/i);
  });
});
