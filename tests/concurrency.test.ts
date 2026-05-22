import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, it } from "vitest";
import { paseto } from "../src/index";
import { BASE_URL, freshDb, signUpAndGetCookie } from "./helpers";

/**
 * Phase C: concurrency invariants on the key-creation path.
 *
 * - The GET /paseto-keys handler must not write. Init seeds the table
 *   at server-startup; the read endpoint reads only.
 * - Concurrent sign-paseto calls racing past a rotation boundary must
 *   collapse to a single new key per rotation interval (within one
 *   instance, behind the per-plugin async mutex).
 *
 * These tests use a local helper that pins the DB reference so the test
 * can inspect mutations directly. The shared `makeAuth` helper does
 * not expose the underlying db.
 */

describe("init seeds the table; GET /paseto-keys does not write", () => {
  it("first GET /paseto-keys returns a key without the handler mutating the table", async () => {
    // The db reference here is the same one inside the auth instance --
    // we can inspect it directly to assert no mutation across the
    // request boundary.
    const db = freshDb();
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(db),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          paseto: { issuer: BASE_URL, audience: BASE_URL },
        }),
      ],
    });

    // First handler call triggers init, which seeds a key.
    const res1 = await auth.handler(
      new Request(`${BASE_URL}/api/auth/paseto-keys`),
    );
    expect(res1.status).toBe(200);
    const initial = await res1.json();
    expect(initial.keys.length).toBe(1);
    expect(db.paseto_keys.length).toBe(1);

    const beforeSecond = [...db.paseto_keys];
    const res2 = await auth.handler(
      new Request(`${BASE_URL}/api/auth/paseto-keys`),
    );
    expect(res2.status).toBe(200);
    // Read should not create a second row.
    expect(db.paseto_keys.length).toBe(1);
    expect(db.paseto_keys).toEqual(beforeSecond);
  });

  it("concurrent first-touch GETs all read from the same seeded key", async () => {
    const db = freshDb();
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(db),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          paseto: { issuer: BASE_URL, audience: BASE_URL },
        }),
      ],
    });

    // Launch 20 simultaneous requests against a fresh DB. Init seeds
    // once during plugin construction (before the first request lands
    // in the handler chain), so all 20 reads see the same row.
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        auth.handler(new Request(`${BASE_URL}/api/auth/paseto-keys`)),
      ),
    );
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(db.paseto_keys.length).toBe(1);
  });
});

describe("rotation race: concurrent signs at the boundary produce one new key", () => {
  it("20 simultaneous /sign-paseto calls after rotation expiry create exactly one fresh key", async () => {
    const db = freshDb();
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "test-secret-that-is-at-least-32-chars-long",
      database: memoryAdapter(db),
      emailAndPassword: { enabled: true },
      plugins: [
        paseto({
          keys: {
            rotationInterval: 1, // 1s, so it expires fast
            gracePeriod: 60 * 60,
          },
          paseto: {
            issuer: BASE_URL,
            audience: BASE_URL,
            expirationTime: "15m",
          },
        }),
      ],
    });

    const cookie = await signUpAndGetCookie(auth);

    // Init seeded one key. Sign once with it (single-thread, no race)
    // so the in-flight mutex map is in a known empty state.
    await auth.handler(
      new Request(`${BASE_URL}/api/auth/sign-paseto`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ payload: { phase: "pre-rotation" } }),
      }),
    );
    expect(db.paseto_keys.length).toBe(1);

    // Wait past the 1s rotation interval so the next sign would
    // ordinarily create a fresh key.
    await new Promise((r) => setTimeout(r, 1_100));

    // Launch 20 simultaneous sign requests. Without the mutex these
    // would each see "latest is expired" and each create. With the
    // mutex they collapse to one creation.
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        auth.handler(
          new Request(`${BASE_URL}/api/auth/sign-paseto`, {
            method: "POST",
            headers: { "content-type": "application/json", cookie },
            body: JSON.stringify({ payload: { phase: "post-rotation" } }),
          }),
        ),
      ),
    );
    expect(results.every((r) => r.status === 200)).toBe(true);

    // Pre-rotation seeded one. Single new key from the mutex collapse.
    // Total = 2.
    expect(db.paseto_keys.length).toBe(2);
  });
});
