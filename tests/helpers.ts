import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { paseto } from "../src/index";

/**
 * Shared test-only helpers. Used by tests/plugin.test.ts and
 * tests/verify-extras.test.ts to spin up better-auth instances with
 * a known-state paseto_keys table.
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
