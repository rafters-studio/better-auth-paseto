import type { GenericEndpointContext } from "@better-auth/core";
import { symmetricEncrypt } from "better-auth/crypto";
import { getPasetoKeysAdapter } from "./adapter";
import type { PasetoKey, PasetoOptions } from "./types";

/**
 * Convert a duration spec to an absolute exp claim (ISO-8601 string).
 *
 * PASETO claims use ISO-8601 strings, not Unix seconds. This is a
 * deliberate spec choice -- timestamps are unambiguous and human-readable.
 */
export function toExpPaseto(
  expirationTime: number | Date | string,
  iat: Date,
): string {
  if (expirationTime instanceof Date) {
    return expirationTime.toISOString();
  }
  if (typeof expirationTime === "number") {
    // Treat as Unix seconds for parity with the JWT plugin's expirationTime number.
    return new Date(expirationTime * 1000).toISOString();
  }
  // Duration string like "15m", "1h", "30s", "7d".
  const seconds = parseDuration(expirationTime);
  return new Date(iat.getTime() + seconds * 1000).toISOString();
}

function parseDuration(s: string): number {
  const match = s.trim().match(/^(\d+)\s*(s|m|h|d)$/i);
  if (!match) {
    throw new Error(
      `Invalid duration "${s}". Expected formats: 30s, 15m, 1h, 7d.`,
    );
  }
  const n = Number(match[1]);
  const unit = match[2]!.toLowerCase();
  switch (unit) {
    case "s":
      return n;
    case "m":
      return n * 60;
    case "h":
      return n * 60 * 60;
    case "d":
      return n * 60 * 60 * 24;
    default:
      throw new Error(`Unreachable: ${unit}`);
  }
}

/**
 * Generate a fresh Ed25519 keypair, exported as JWK JSON. PASETO v4.public
 * is fixed at Ed25519 -- there is no algorithm choice, by spec design.
 */
export async function generateExportedKeyPair() {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const publicWebKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateWebKey = await crypto.subtle.exportKey(
    "jwk",
    keyPair.privateKey,
  );
  return { publicWebKey, privateWebKey };
}

/** Create and store a new keypair. */
export async function createPasetoKey(
  ctx: GenericEndpointContext,
  options?: PasetoOptions,
): Promise<PasetoKey> {
  const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
  const stringifiedPrivate = JSON.stringify(privateWebKey);
  const encryptionOn = !options?.keys?.disablePrivateKeyEncryption;

  const key: Omit<PasetoKey, "id"> = {
    publicKey: JSON.stringify(publicWebKey),
    privateKey: encryptionOn
      ? JSON.stringify(
          await symmetricEncrypt({
            key: ctx.context.secretConfig,
            data: stringifiedPrivate,
          }),
        )
      : stringifiedPrivate,
    createdAt: new Date(),
    ...(options?.keys?.rotationInterval
      ? {
          expiresAt: new Date(
            Date.now() + options.keys.rotationInterval * 1000,
          ),
        }
      : {}),
  };

  const adapter = getPasetoKeysAdapter(ctx.context.adapter, options);
  return await adapter.createKey(ctx, key);
}

/**
 * Decode a base64url string to bytes. Same convention JWK uses.
 */
export function base64UrlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Extract the raw Ed25519 private seed (32 bytes) and public key (32 bytes)
 * from an OKP JWK. The PASETO v4.public secret key is the 64-byte
 * concatenation of seed || public, which is what every conforming PASETO
 * library accepts.
 */
export function jwkToPasetoSecretKey(jwk: {
  kty: string;
  crv: string;
  x: string;
  d?: string;
}): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error(`Expected OKP/Ed25519 JWK, got ${jwk.kty}/${jwk.crv}.`);
  }
  if (!jwk.d) throw new Error("JWK is missing private component (d).");
  const seed = base64UrlDecode(jwk.d);
  const pub = base64UrlDecode(jwk.x);
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes.");
  if (pub.length !== 32) throw new Error("Ed25519 public key must be 32 bytes.");
  const out = new Uint8Array(64);
  out.set(seed, 0);
  out.set(pub, 32);
  return out;
}

/** Extract the raw Ed25519 public key (32 bytes) from an OKP JWK. */
export function jwkToPasetoPublicKey(jwk: {
  kty: string;
  crv: string;
  x: string;
}): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error(`Expected OKP/Ed25519 JWK, got ${jwk.kty}/${jwk.crv}.`);
  }
  const pub = base64UrlDecode(jwk.x);
  if (pub.length !== 32) throw new Error("Ed25519 public key must be 32 bytes.");
  return pub;
}
