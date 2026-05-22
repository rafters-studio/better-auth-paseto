import type { GenericEndpointContext } from "@better-auth/core";
import { BetterAuthError } from "@better-auth/core/error";
import { symmetricDecrypt } from "better-auth/crypto";
import { sign as pasetoSign } from "paseto-ts/v4";
import type { PasetoClaims, PasetoOptions } from "./types";
import { ensureFreshKey, jwkToPasetoSecretKey, toExpPaseto } from "./utils";

/**
 * Sign a PASETO v4.public token.
 *
 * The kid lives in the authenticated footer (not a header) per PASETO's
 * "no tamperable header" design. Verifiers read the footer first to pick
 * the right key, then verify the token body against that key.
 */
export async function signPaseto(
  ctx: GenericEndpointContext,
  config: {
    options?: PasetoOptions;
    payload: PasetoClaims;
  },
): Promise<string> {
  const { options } = config;
  const payload = { ...config.payload } as PasetoClaims;

  const now = new Date();
  const iat = payload.iat ? new Date(payload.iat) : now;
  payload.iat ??= iat.toISOString();

  const defaultExpSpec = options?.paseto?.expirationTime ?? "15m";
  payload.exp ??= toExpPaseto(defaultExpSpec, iat);

  const baseURLOrigin =
    typeof ctx.context.options.baseURL === "string"
      ? ctx.context.options.baseURL
      : "";

  payload.iss ??= options?.paseto?.issuer ?? baseURLOrigin;
  payload.aud ??= options?.paseto?.audience ?? baseURLOrigin;

  // Custom / remote signer path. The caller is responsible for any kid
  // tracking in this mode -- usually they are signing via a KMS that owns
  // its own key identifiers.
  if (options?.paseto?.sign) {
    return options.paseto.sign(payload);
  }

  // ensureFreshKey collapses concurrent sign calls that race past a
  // rotation boundary into a single key creation per instance. The
  // helper does its own latest-key lookup + freshness check, so the
  // sign path no longer queries the adapter for the latest key
  // separately.
  const key = await ensureFreshKey(
    { adapter: ctx.context.adapter, secretConfig: ctx.context.secretConfig },
    options,
    ctx,
  );

  const encryptionOn = !options?.keys?.disablePrivateKeyEncryption;
  const privateWebKeyJson = encryptionOn
    ? await symmetricDecrypt({
        key: ctx.context.secretConfig,
        data: JSON.parse(key.privateKey),
      }).catch(() => {
        throw new BetterAuthError(
          "Failed to decrypt private key. The better-auth secret in use does not match the one that encrypted the key. Either restore the original secret, clear the paseto_keys table, or disable private-key encryption.",
        );
      })
    : key.privateKey;

  const privateJwk = JSON.parse(privateWebKeyJson);
  const secretKey = jwkToPasetoSecretKey(privateJwk);

  // Cast to paseto-ts's Payload: it uses `any` indexed access while our
  // PasetoClaims uses `unknown` per project convention. The shape matches.
  return pasetoSign(secretKey, payload as unknown as Record<string, unknown>, {
    footer: { kid: key.id },
  });
}

/**
 * Mint a session-derived token. Equivalent to better-auth's JWT plugin's
 * getJwtToken: build the payload from the session and sign.
 */
export async function getPasetoToken(
  ctx: GenericEndpointContext,
  options?: PasetoOptions,
): Promise<string> {
  const session = ctx.context.session!;
  const payload = options?.paseto?.definePayload
    ? await options.paseto.definePayload(session)
    : session.user;

  return await signPaseto(ctx, {
    options,
    payload: {
      iat: new Date().toISOString(),
      ...payload,
      sub:
        (await options?.paseto?.getSubject?.(session)) ?? session.user.id,
    } as PasetoClaims,
  });
}
