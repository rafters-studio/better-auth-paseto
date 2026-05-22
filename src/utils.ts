import type {
  BetterAuthOptions,
  GenericEndpointContext,
} from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import type { SecretConfig } from "@better-auth/core";
import { symmetricEncrypt } from "better-auth/crypto";
import { getPasetoKeysAdapter } from "./adapter";
import type { PasetoKey, PasetoOptions } from "./types";

/**
 * The minimum context shape `createPasetoKey` and `ensureFreshKey` need.
 * Accepts either a `GenericEndpointContext` (use `ctx.context`) or a
 * better-auth `AuthContext` passed from the plugin `init` hook. The
 * narrow shape lets the same helper run from request handlers and from
 * server-startup init without synthesising fake contexts.
 */
export interface KeyOpContext {
  adapter: DBAdapter<BetterAuthOptions>;
  secretConfig: string | SecretConfig;
}

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

/**
 * Create and store a new keypair.
 *
 * `ctx` is the narrow shape -- caller decides whether to pass a
 * `GenericEndpointContext`'s `.context` (request handler path) or a
 * better-auth `AuthContext` directly (plugin init path).
 *
 * `requestCtx` is only needed when `options.adapter.createKey` is set
 * (the user-supplied adapter override needs the request context to pass
 * through to whatever external store they wired up). Calls from init,
 * where no request exists, will throw if a user adapter is configured
 * -- those installations must seed their first key out-of-band.
 */
export async function createPasetoKey(
  ctx: KeyOpContext,
  options?: PasetoOptions,
  requestCtx?: GenericEndpointContext,
): Promise<PasetoKey> {
  const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
  const stringifiedPrivate = JSON.stringify(privateWebKey);
  const encryptionOn = !options?.keys?.disablePrivateKeyEncryption;

  const key: Omit<PasetoKey, "id"> = {
    publicKey: JSON.stringify(publicWebKey),
    privateKey: encryptionOn
      ? JSON.stringify(
          await symmetricEncrypt({
            key: ctx.secretConfig,
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

  const adapter = getPasetoKeysAdapter(ctx.adapter, options);
  return await adapter.createKey(key, requestCtx);
}

/**
 * Per-plugin-instance async mutex for key creation. Keyed by adapter
 * identity so each better-auth instance gets its own slot. Within a
 * single Node / Worker / Bun instance this collapses N concurrent
 * createPasetoKey calls into one DB write. Across instances the race
 * remains and may briefly produce duplicate rows -- documented in the
 * README under "Key rotation under load."
 */
const keyCreateInFlight = new WeakMap<object, Promise<PasetoKey>>();

/**
 * Ensure a fresh, non-expired key exists for signing. If one already
 * does, returns it. If not, creates one -- collapsing concurrent
 * callers behind a shared promise so the table does not gain duplicate
 * rows during burst traffic.
 *
 * The mutex re-checks the latest key on entry: another in-flight
 * creation may have already satisfied the need by the time this caller
 * acquired the lock.
 */
export async function ensureFreshKey(
  ctx: KeyOpContext,
  options?: PasetoOptions,
  requestCtx?: GenericEndpointContext,
): Promise<PasetoKey> {
  const adapterKey = ctx.adapter as unknown as object;
  const existing = keyCreateInFlight.get(adapterKey);
  if (existing) return existing;

  const promise = (async (): Promise<PasetoKey> => {
    // Re-check via adapter directly. The custom-adapter path (when
    // options.adapter.getKeys is configured) cannot re-check without a
    // request context, so skip the optimisation and just create.
    if (!options?.adapter?.getKeys) {
      const latest = await ctx.adapter.findMany<PasetoKey>({
        model: "paseto_keys",
        sortBy: { field: "createdAt", direction: "desc" },
        limit: 1,
      });
      const latestKey = latest?.[0];
      if (
        latestKey &&
        (!latestKey.expiresAt || latestKey.expiresAt >= new Date())
      ) {
        return latestKey;
      }
    }
    return createPasetoKey(ctx, options, requestCtx);
  })();

  keyCreateInFlight.set(adapterKey, promise);
  try {
    return await promise;
  } finally {
    keyCreateInFlight.delete(adapterKey);
  }
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

/** Encode bytes as base64url (no padding). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Convert an Ed25519 OKP JWK private key to a PASERK k4.secret string.
 * PASETO v4.public secret keys are the 64-byte concatenation of seed||public,
 * wrapped in the PASERK envelope `k4.secret.<base64url>` that paseto-ts and
 * every conforming PASETO library expects.
 */
export function jwkToPasetoSecretKey(jwk: {
  kty: string;
  crv: string;
  x: string;
  d?: string;
}): string {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error(`Expected OKP/Ed25519 JWK, got ${jwk.kty}/${jwk.crv}.`);
  }
  if (!jwk.d) throw new Error("JWK is missing private component (d).");
  const seed = base64UrlDecode(jwk.d);
  const pub = base64UrlDecode(jwk.x);
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes.");
  if (pub.length !== 32) throw new Error("Ed25519 public key must be 32 bytes.");
  const combined = new Uint8Array(64);
  combined.set(seed, 0);
  combined.set(pub, 32);
  return `k4.secret.${base64UrlEncode(combined)}`;
}

/** Convert an Ed25519 OKP JWK public key to a PASERK k4.public string. */
export function jwkToPasetoPublicKey(jwk: {
  kty: string;
  crv: string;
  x: string;
}): string {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error(`Expected OKP/Ed25519 JWK, got ${jwk.kty}/${jwk.crv}.`);
  }
  const pub = base64UrlDecode(jwk.x);
  if (pub.length !== 32) throw new Error("Ed25519 public key must be 32 bytes.");
  return `k4.public.${base64UrlEncode(pub)}`;
}
