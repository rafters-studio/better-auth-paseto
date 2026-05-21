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
export { verifyPaseto } from "./verify";

declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    paseto: {
      creator: typeof paseto;
    };
  }
}

const signPasetoBodySchema = z.object({
  payload: z.record(z.string(), z.any()),
  overrideOptions: z.record(z.string(), z.any()).optional(),
});

const verifyPasetoBodySchema = z.object({
  token: z.string(),
  issuer: z.string().optional(),
});

/**
 * PASETO v4.public plugin for better-auth.
 *
 * Mirrors the JWT plugin's surface (endpoints, hooks, options shape) so it
 * is a drop-in replacement. The wire format is PASETO instead of JWS, with
 * no algorithm-confusion attack surface and a fixed Ed25519 keypair scheme.
 */
export const paseto = <O extends PasetoOptions>(options?: O) => {
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

          const adapter = getPasetoKeysAdapter(ctx.context.adapter, options);
          let keys = await adapter.getAllKeys(ctx);
          if (!keys || keys.length === 0) {
            await createPasetoKey(ctx, options);
            keys = await adapter.getAllKeys(ctx);
          }
          if (!keys?.length) {
            throw new BetterAuthError(
              "No PASETO keys found. Ensure the paseto_keys table is reachable.",
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

      /** Sign an arbitrary payload as a PASETO token. */
      signPaseto: createAuthEndpoint(
        "/sign-paseto",
        {
          method: "POST",
          metadata: {
            $Infer: {
              body: {} as {
                payload: PasetoClaims;
                overrideOptions?: PasetoOptions;
              },
            },
          },
          body: signPasetoBodySchema,
        },
        async (c) => {
          const token = await signPaseto(c, {
            options: { ...options, ...c.body.overrideOptions },
            payload: c.body.payload as PasetoClaims,
          });
          return c.json({ token });
        },
      ),

      /** Verify a PASETO token. Returns the payload or null. */
      verifyPaseto: createAuthEndpoint(
        "/verify-paseto",
        {
          method: "POST",
          metadata: {
            $Infer: {
              body: {} as { token: string; issuer?: string },
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
          const overrideOptions = ctx.body.issuer
            ? {
                ...options,
                paseto: { ...options?.paseto, issuer: ctx.body.issuer },
              }
            : options;
          const payload = await verifyPasetoHelper(ctx.body.token, overrideOptions);
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
