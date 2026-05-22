import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { generateExportedKeyPair } from "../src/utils";
import { makeAuthWithSeededKeys, verifyVia } from "./helpers";

/**
 * Property-based coverage for the verifier's negative path. The verifier
 * is the only public surface that consumers point at attacker-controlled
 * input -- it must never throw, and it must always resolve to a null
 * payload when the input is anything other than a token signed by a key
 * the plugin knows about.
 *
 * Each property runs 100 cases.
 */

describe("verifier never throws, always returns null on bad input", () => {
  it("random byte strings are rejected without panic", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "fuzz-1", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 0, maxLength: 256 }),
        async (s) => {
          const payload = await verifyVia(auth, s);
          expect(payload).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });

  it("valid v4.public header with garbage payload is rejected", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "fuzz-2", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 0, maxLength: 256 }),
        async (garbage) => {
          const token = `v4.public.${garbage}`;
          const payload = await verifyVia(auth, token);
          expect(payload).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });

  it("random footer kid that does not match any stored key is rejected", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "fuzz-3", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 64 }),
        async (kid) => {
          // Build a syntactically valid 4-segment token with a random
          // base64url-shaped footer. The body segment is garbage so the
          // signature check fails even if the kid somehow collides; the
          // verifier path that matters is "footer has unknown kid
          // shape" -> null without throwing.
          const fakeBody = btoa("garbage")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
          const footer = btoa(JSON.stringify({ kid }))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
          const token = `v4.public.${fakeBody}.${footer}`;
          const payload = await verifyVia(auth, token);
          expect(payload).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });

  it("footer with non-kid fields is rejected without throwing", async () => {
    const { publicWebKey, privateWebKey } = await generateExportedKeyPair();
    const auth = makeAuthWithSeededKeys([
      { id: "fuzz-4", publicKey: publicWebKey, privateKey: privateWebKey },
    ]);

    await fc.assert(
      fc.asyncProperty(
        fc.dictionary(fc.string(), fc.string()),
        async (footerObj) => {
          // Strip kid so the verifier hits the missing-kid branch.
          delete (footerObj as Record<string, unknown>).kid;
          const fakeBody = btoa("garbage")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
          const footer = btoa(JSON.stringify(footerObj))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
          const token = `v4.public.${fakeBody}.${footer}`;
          const payload = await verifyVia(auth, token);
          expect(payload).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });
});
