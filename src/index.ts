import type { BetterAuthPlugin } from "@better-auth/core";
import {
  createAuthEndpoint,
  createAuthMiddleware,
} from "@better-auth/core/api";
import { BetterAuthError } from "@better-auth/core/error";
import * as z from "zod";
import { APIError, sessionMiddleware } from "better-auth/api";
import { mergeSchema } from "better-auth/db";
import { getPasetoKeysAdapter } from "./adapter";
import { schema } from "./schema";
import { getPasetoToken, signPaseto } from "./sign";
import type { PasetoClaims, PasetoOptions } from "./types";
import { createPasetoKey } from "./utils";
import { verifyPaseto as verifyPasetoHelper } from "./verify";

export { signPaseto } from "./sign";
export type * from "./types";
export { createPasetoKey, generateExportedKeyPair, toExpPaseto } from "./utils";
export { verifyPaseto, verifyPasetoWithReason } from "./verify";

declare module "@better-auth/core" {
  // TypeScript requires merged interface declarations to use the same
  // type parameter names as the base. The names appear unused here but
  // changing them would break declaration merging with @better-auth/core.
  // oxlint-disable-next-line no-unused-vars
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    paseto: {
      creator: typeof paseto;
    };
  }
}

// Body schema for /sign-paseto. `payload` carries supplementary
// application-level claims only -- the security-relevant claims
// (sub/iss/aud/iat/exp) are sourced from the session and plugin options,
// never from the request body. Caller-supplied values for those keys are
// stripped before signing.
const signPasetoBodySchema = z.object({
  payload: z.record(z.string(), z.any()),
});

// Body schema for /verify-paseto. Issuer and other claim expectations are
// resolved from plugin options on the server side, not from the request
// body -- otherwise a verifier endpoint would trust the caller's claim of
// what to expect, defeating the iss check.
const verifyPasetoBodySchema = z.object({
  token: z.string(),
});

/**
 * PASETO v4.public plugin for better-auth.
 *
 * Mirrors the JWT plugin's surface (endpoints, hooks, options shape) so it
 * is a drop-in replacement. The wire format is PASETO instead of JWS, with
 * no algorithm-confusion attack surface and a fixed Ed25519 keypair scheme.
 */
export const paseto = <O extends PasetoOptions>(
  options?: O,
): BetterAuthPlugin => {
  // Remote-url + custom-signer consistency check.
  if (options?.paseto?.sign && !options.keys?.remoteUrl) {
    throw new BetterAuthError(
      "options.keys.remoteUrl must be set when using options.paseto.sign",
    );
  }

  const keysPath = options?.keys?.keysPath ?? "/paseto-keys";
  if (
    typeof keysPath !== "string" ||
    keysPath.length === 0 ||
    !keysPath.startsWith("/") ||
    keysPath.includes("..")
  ) {
    throw new BetterAuthError(
      "options.keys.keysPath must be a non-empty string starting with '/' and not contain '..'",
    );
  }

  return {
    id: "paseto",
    options: options as NoInfer<O>,
    /**
     * Two startup checks:
     *
     * 1. Probe Web Crypto for Ed25519 support. Older runtimes fail
     *    cryptically on the first sign call; failing here at init names
     *    the cause for the operator.
     *
     * 2. Ensure at least one signing key exists in the table. Without
     *    this, the first GET /paseto-keys would have to lazily create a
     *    key on a read path -- a HTTP-semantics violation and a race
     *    surface across concurrent first-touches. Moving the seed to
     *    init means reads stay reads.
     *
     * The seed step is skipped when `keys.remoteUrl` is set (no local
     * table to seed) or when `options.adapter` is configured (init has
     * no request context, and a user adapter may need one -- those
     * installations seed out-of-band).
     */
    init: async (initCtx) => {
      try {
        await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
      } catch (err) {
        throw new BetterAuthError(
          "@rafters/better-auth-paseto requires Web Crypto Ed25519 support. " +
            "Verified runtimes: Node 20+, Cloudflare Workers, Bun >= 1.1.0. " +
            `Underlying error: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      if (options?.keys?.remoteUrl || options?.adapter) return;

      const existing = await initCtx.adapter.findMany({
        model: "paseto_keys",
        limit: 1,
      });
      if (existing && existing.length > 0) return;

      await createPasetoKey(
        { adapter: initCtx.adapter, secretConfig: initCtx.secret },
        options,
      );
    },
    endpoints: {
      /**
       * Public-key set. JWKS-shaped on the wire because Ed25519 keys are
       * representable as OKP JWKs -- any JWK-aware verifier can read them.
       * Consumers that need raw PASETO public keys decode the `x` field.
       */
      getPasetoKeys: createAuthEndpoint(
        keysPath,
        {
          method: "GET",
          metadata: {
            openapi: {
              operationId: "getPasetoKeys",
              description:
                "Get the PASETO public-key set (JWKS-shaped for interop)",
              responses: {
                "200": {
                  description: "Key set retrieved successfully",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          keys: {
                            type: "array",
                            items: {
                              type: "object",
                              properties: {
                                kid: { type: "string" },
                                kty: { type: "string", enum: ["OKP"] },
                                crv: { type: "string", enum: ["Ed25519"] },
                                alg: { type: "string", enum: ["EdDSA"] },
                                use: { type: "string", enum: ["sig"] },
                                x: { type: "string" },
                              },
                              required: ["kid", "kty", "crv", "x"],
                            },
                          },
                        },
                        required: ["keys"],
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          if (options?.keys?.remoteUrl) {
            throw new APIError("NOT_FOUND");
          }

          // Read-only path. The init hook above guarantees at least one
          // key exists at server-startup time (except for remote-url or
          // custom-adapter installations, which seed out-of-band). If
          // the table is empty here something has gone wrong externally
          // -- truncation, migration not applied, etc -- and the error
          // points the operator at the recovery action.
          const adapter = getPasetoKeysAdapter(ctx.context.adapter, options);
          const keys = await adapter.getAllKeys(ctx);
          if (!keys?.length) {
            throw new BetterAuthError(
              "No PASETO keys found. Either init did not run (check plugin order) " +
                "or the paseto_keys table was cleared externally.",
            );
          }

          const now = Date.now();
          const DEFAULT_GRACE_PERIOD = 60 * 60 * 24 * 30;
          const gracePeriod =
            (options?.keys?.gracePeriod ?? DEFAULT_GRACE_PERIOD) * 1000;

          const live = keys.filter((k) => {
            if (!k.expiresAt) return true;
            return k.expiresAt.getTime() + gracePeriod > now;
          });

          return ctx.json({
            keys: live.map((k) => {
              const publicJwk = JSON.parse(k.publicKey);
              return {
                kid: k.id,
                kty: "OKP" as const,
                crv: "Ed25519" as const,
                alg: "EdDSA" as const,
                use: "sig" as const,
                x: publicJwk.x,
              };
            }),
          });
        },
      ),

      /** Mint a session-derived PASETO. Requires an active session. */
      getToken: createAuthEndpoint(
        "/token",
        {
          method: "GET",
          requireHeaders: true,
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              operationId: "getPasetoToken",
              description: "Get a PASETO token derived from the current session",
              responses: {
                200: {
                  description: "Success",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: { token: { type: "string" } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          const token = await getPasetoToken(ctx, options);
          return ctx.json({ token });
        },
      ),

      /**
       * Sign a PASETO token for the active session, attaching supplementary
       * claims supplied by the caller.
       *
       * Requires an authenticated session. Security-relevant claims are
       * always sourced from server state, not the request body:
       * - `sub` from the session (via `paseto.getSubject` or `user.id`)
       * - `iss`, `aud`, `exp` from plugin options (or `baseURL` default)
       * - `iat` from the current server time
       *
       * Anything else the caller supplies in `payload` is merged through.
       */
      signPaseto: createAuthEndpoint(
        "/sign-paseto",
        {
          method: "POST",
          requireHeaders: true,
          use: [sessionMiddleware],
          metadata: {
            $Infer: {
              body: {} as { payload: PasetoClaims },
            },
          },
          body: signPasetoBodySchema,
        },
        async (c) => {
          const session = c.context.session!;
          const body = c.body.payload as PasetoClaims;
          // Strip security-relevant claims from the caller's payload; they
          // are reset from server state below.
          const {
            sub: _sub,
            iss: _iss,
            aud: _aud,
            iat: _iat,
            exp: _exp,
            ...supplementary
          } = body;
          const sub =
            (await options?.paseto?.getSubject?.(session)) ?? session.user.id;
          const token = await signPaseto(c, {
            options,
            payload: {
              ...supplementary,
              iat: new Date().toISOString(),
              sub,
            } as PasetoClaims,
          });
          return c.json({ token });
        },
      ),

      /**
       * Verify a PASETO token against the server's configured issuer and
       * audience. Returns the payload or null.
       *
       * Claim expectations (iss/aud) are taken from plugin options -- the
       * request body cannot influence them. A verifier endpoint that lets
       * the caller choose what to expect is not a verifier; it is a
       * rubber-stamp.
       */
      verifyPaseto: createAuthEndpoint(
        "/verify-paseto",
        {
          method: "POST",
          metadata: {
            $Infer: {
              body: {} as { token: string },
              response: {} as {
                payload: {
                  sub: string;
                  aud: string | string[];
                  [k: string]: any;
                } | null;
              },
            },
          },
          body: verifyPasetoBodySchema,
        },
        async (ctx) => {
          const payload = await verifyPasetoHelper(ctx.body.token, options);
          return ctx.json({ payload });
        },
      ),
    },
    hooks: {
      after: [
        {
          matcher(context) {
            return context.path === "/get-session";
          },
          handler: createAuthMiddleware(async (ctx) => {
            if (options?.disableSettingHeader) return;

            const session = ctx.context.session || ctx.context.newSession;
            if (session && session.session) {
              const token = await getPasetoToken(ctx, options);
              const exposed =
                ctx.context.responseHeaders?.get(
                  "access-control-expose-headers",
                ) || "";
              const set = new Set(
                exposed.split(",").map((h) => h.trim()).filter(Boolean),
              );
              set.add("set-auth-paseto");
              ctx.setHeader("set-auth-paseto", token);
              ctx.setHeader(
                "Access-Control-Expose-Headers",
                Array.from(set).join(", "),
              );
            }
          }),
        },
      ],
    },
    schema: mergeSchema(schema, options?.schema),
  } satisfies BetterAuthPlugin;
};

export { getPasetoToken };
