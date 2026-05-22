import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { paseto } from "../src/index";

/**
 * Shared test-only helpers. Used across every test file to spin up
 * better-auth instances, drive sign-up + cookie flows, and round-trip
 * tokens through the verify endpoint.
 */

export const BASE_URL = "https://test.example.com";

export function freshDb(): Record<string, any[]> {
  return {
    user: [],
    session: [],
    account: [],
    verification: [],
    paseto_keys: [],
  };
}

export interface SeededKey {
  id: string;
  publicKey: object;
  privateKey: object;
  createdAt?: Date;
  expiresAt?: Date;
}

/**
 * Build a better-auth instance pre-loaded with known keypairs in the
 * paseto_keys table. Used to drive verification-side tests against
 * tokens constructed externally (expired, wrong-issuer, footer-rebased,
 * future-nbf, etc).
 *
 * Defaults: disablePrivateKeyEncryption=true (matches raw JWK storage
 * of the seeded rows), issuer/audience pinned to BASE_URL. Override
 * via `extraOptions`.
 */
export function makeAuthWithSeededKeys(
  keys: SeededKey[],
  extraOptions?: Parameters<typeof paseto>[0],
) {
  const db: Record<string, any[]> = {
    ...freshDb(),
    paseto_keys: keys.map((k) => ({
      id: k.id,
      publicKey: JSON.stringify(k.publicKey),
      privateKey: JSON.stringify(k.privateKey),
      createdAt: k.createdAt ?? new Date(),
      ...(k.expiresAt ? { expiresAt: k.expiresAt } : {}),
    })),
  };
  return betterAuth({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-chars-long",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    plugins: [
      paseto({
        keys: { disablePrivateKeyEncryption: true },
        paseto: {
          issuer: BASE_URL,
          audience: BASE_URL,
        },
        ...extraOptions,
      }),
    ],
  });
}

/**
 * Build a better-auth instance with an empty paseto_keys table. The
 * plugin's init hook seeds the first key when the handler chain runs.
 */
export function makeAuth(extraOptions?: Parameters<typeof paseto>[0]) {
  return betterAuth({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-chars-long",
    database: memoryAdapter(freshDb()),
    emailAndPassword: { enabled: true },
    plugins: [
      paseto({
        paseto: {
          issuer: BASE_URL,
          audience: BASE_URL,
          expirationTime: "15m",
        },
        ...extraOptions,
      }),
    ],
  });
}

/**
 * Sign up a user via /sign-up/email and return the set-cookie header.
 * Throws if sign-up did not return one so callers never proceed with a
 * missing cookie.
 */
export async function signUpAndGetCookie(
  auth: ReturnType<typeof makeAuth>,
  email = "alice@example.com",
): Promise<string> {
  const res = await auth.handler(
    new Request(`${BASE_URL}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        password: "correct-horse-battery-staple",
        name: "Alice",
      }),
    }),
  );
  const cookie = res.headers.get("set-cookie");
  if (!cookie) {
    throw new Error(`sign-up did not return a cookie (status ${res.status})`);
  }
  return cookie;
}

/**
 * Round-trip a token through /verify-paseto and return the `payload`
 * field (null on rejection, payload object on success).
 */
export async function verifyVia(
  auth: ReturnType<typeof makeAuth>,
  token: string,
): Promise<unknown> {
  const res = await auth.handler(
    new Request(`${BASE_URL}/api/auth/verify-paseto`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    }),
  );
  const body = await res.json();
  return body.payload;
}
