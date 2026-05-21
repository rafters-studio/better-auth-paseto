import { describe, expect, it } from "vitest";
import { sign as pasetoSign, verify as pasetoVerify } from "paseto-ts/v4";
import {
  generateExportedKeyPair,
  jwkToPasetoPublicKey,
  jwkToPasetoSecretKey,
} from "../src/utils";

/**
 * These tests exercise the sign/verify primitive in isolation, without the
 * better-auth plugin runtime. That keeps them fast and pins down the
 * paseto-ts API assumptions our plugin code depends on. Plugin-level
 * integration tests live in plugin.test.ts.
 */

async function freshKeys() {
  const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
  return {
    publicJwk: publicWebKey,
    privateJwk: privateWebKey,
    secret: jwkToPasetoSecretKey(privateWebKey as any),
    pub: jwkToPasetoPublicKey(publicWebKey as any),
  };
}

describe("PASETO v4.public sign/verify roundtrip", () => {
  it("signs and verifies a basic payload", async () => {
    const { secret, pub } = await freshKeys();
    const payload = {
      sub: "user-123",
      iss: "https://example.com",
      aud: "https://example.com",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    };
    const token = pasetoSign(secret, payload);
    expect(token.startsWith("v4.public.")).toBe(true);

    const { payload: verified } = pasetoVerify(pub, token);
    expect(verified.sub).toBe("user-123");
    expect(verified.iss).toBe("https://example.com");
  });

  it("kid round-trips through the footer", async () => {
    const { secret, pub } = await freshKeys();
    const kid = "key-abc-123";
    const token = pasetoSign(
      secret,
      {
        sub: "u",
        aud: "a",
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      { footer: { kid } },
    );

    // PASETO format: v4.public.<payload>.<footer>
    const parts = token.split(".");
    expect(parts.length).toBe(4);

    const { footer } = pasetoVerify(pub, token);
    const footerObj =
      typeof footer === "string" ? JSON.parse(footer) : footer;
    expect(footerObj?.kid).toBe(kid);
  });

  it("rejects a token signed with a different key", async () => {
    const keysA = await freshKeys();
    const keysB = await freshKeys();
    const token = pasetoSign(keysA.secret, {
      sub: "u",
      aud: "a",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(() => pasetoVerify(keysB.pub, token)).toThrow();
  });

  it("rejects a tampered token body", async () => {
    const { secret, pub } = await freshKeys();
    const token = pasetoSign(secret, {
      sub: "u",
      aud: "a",
      iat: new Date().toISOString(),
      exp: new Date(Date.now() + 60_000).toISOString(),
    });
    // Flip a character in the payload segment.
    const parts = token.split(".");
    const payloadSeg = parts[2]!;
    const flipped =
      payloadSeg.slice(0, -1) +
      (payloadSeg.slice(-1) === "A" ? "B" : "A");
    const tampered = [parts[0], parts[1], flipped].join(".");
    expect(() => pasetoVerify(pub, tampered)).toThrow();
  });

  it("rejects a tampered footer", async () => {
    const { secret, pub } = await freshKeys();
    const token = pasetoSign(
      secret,
      {
        sub: "u",
        aud: "a",
        iat: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
      },
      { footer: { kid: "original" } },
    );
    const parts = token.split(".");
    const tamperedFooter = btoa(JSON.stringify({ kid: "evil" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const tampered = [parts[0], parts[1], parts[2], tamperedFooter].join(".");
    expect(() => pasetoVerify(pub, tampered)).toThrow();
  });

  it("does not enforce exp on verify by default (plugin layer does)", async () => {
    // paseto-ts validates exp at sign-time but treats verify's
    // validatePayload as opt-in for *future* claims like nbf, not for
    // already-expired tokens. Our plugin's verifyPaseto wrapper is what
    // enforces exp on the verify side -- pinned in plugin.test.ts.
    // This test documents the library behavior we're relying on.
    const { secret, pub } = await freshKeys();
    const expired = pasetoSign(
      secret,
      {
        sub: "u",
        aud: "a",
        iat: new Date(Date.now() - 120_000).toISOString(),
        exp: new Date(Date.now() - 60_000).toISOString(),
      },
      { validatePayload: false },
    );
    const { payload } = pasetoVerify(pub, expired);
    expect(payload.sub).toBe("u");
  });
});
