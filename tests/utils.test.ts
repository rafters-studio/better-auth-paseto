import { describe, expect, it } from "vitest";
import {
  base64UrlDecode,
  generateExportedKeyPair,
  jwkToPasetoPublicKey,
  jwkToPasetoSecretKey,
  toExpPaseto,
} from "../src/utils";

describe("toExpPaseto", () => {
  const iat = new Date("2026-01-01T00:00:00Z");

  it("treats number as Unix seconds", () => {
    const exp = toExpPaseto(1735689600, iat);
    expect(exp).toBe(new Date(1735689600 * 1000).toISOString());
  });

  it("passes Date through as ISO-8601", () => {
    const d = new Date("2026-06-01T12:00:00Z");
    expect(toExpPaseto(d, iat)).toBe(d.toISOString());
  });

  it("parses seconds duration", () => {
    expect(toExpPaseto("30s", iat)).toBe("2026-01-01T00:00:30.000Z");
  });

  it("parses minutes duration", () => {
    expect(toExpPaseto("15m", iat)).toBe("2026-01-01T00:15:00.000Z");
  });

  it("parses hours duration", () => {
    expect(toExpPaseto("2h", iat)).toBe("2026-01-01T02:00:00.000Z");
  });

  it("parses days duration", () => {
    expect(toExpPaseto("7d", iat)).toBe("2026-01-08T00:00:00.000Z");
  });

  it("is case-insensitive for unit", () => {
    expect(toExpPaseto("15M", iat)).toBe("2026-01-01T00:15:00.000Z");
  });

  it("tolerates whitespace", () => {
    expect(toExpPaseto("  15m  ", iat)).toBe("2026-01-01T00:15:00.000Z");
  });

  it("throws on invalid duration format", () => {
    expect(() => toExpPaseto("forever", iat)).toThrow(/Invalid duration/);
    expect(() => toExpPaseto("15", iat)).toThrow(/Invalid duration/);
    expect(() => toExpPaseto("15y", iat)).toThrow(/Invalid duration/);
  });
});

describe("base64UrlDecode", () => {
  it("decodes a basic value", () => {
    const out = base64UrlDecode("SGVsbG8");
    expect(new TextDecoder().decode(out)).toBe("Hello");
  });

  it("decodes a value with url-safe characters", () => {
    // base64url uses '-' for '+' and '_' for '/'. "_-A" translates to "/+A"
    // which decodes to bytes 0xff, 0xe0.
    const out = base64UrlDecode("_-A");
    expect(out.length).toBe(2);
    expect(out[0]).toBe(0xff);
    expect(out[1]).toBe(0xe0);
  });

  it("handles missing padding", () => {
    expect(base64UrlDecode("SGk").length).toBe(2);
    expect(base64UrlDecode("SGk=").length).toBe(2);
  });
});

describe("Ed25519 JWK <-> PASETO key conversion", () => {
  it("round-trips through generateExportedKeyPair", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    expect(publicWebKey.kty).toBe("OKP");
    expect(publicWebKey.crv).toBe("Ed25519");
    expect(typeof publicWebKey.x).toBe("string");
    expect(privateWebKey.kty).toBe("OKP");
    expect(privateWebKey.crv).toBe("Ed25519");
    expect(typeof privateWebKey.d).toBe("string");

    const secret = jwkToPasetoSecretKey(privateWebKey as any);
    expect(secret.startsWith("k4.secret.")).toBe(true);

    const pub = jwkToPasetoPublicKey(publicWebKey as any);
    expect(pub.startsWith("k4.public.")).toBe(true);
  });

  it("rejects non-OKP JWK", () => {
    expect(() =>
      jwkToPasetoPublicKey({ kty: "RSA", crv: "Ed25519", x: "abc" }),
    ).toThrow(/OKP\/Ed25519/);
  });

  it("rejects wrong curve", () => {
    expect(() =>
      jwkToPasetoPublicKey({ kty: "OKP", crv: "X25519", x: "abc" }),
    ).toThrow(/OKP\/Ed25519/);
  });

  it("rejects private-key extraction when d is missing", () => {
    expect(() =>
      jwkToPasetoSecretKey({ kty: "OKP", crv: "Ed25519", x: "abc" }),
    ).toThrow(/missing private component/);
  });
});
