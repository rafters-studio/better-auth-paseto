import type { GenericEndpointContext } from "@better-auth/core";
import { getCurrentAuthContext } from "@better-auth/core/context";
import { verify as pasetoVerify } from "paseto-ts/v4";
import { getPasetoKeysAdapter } from "./adapter";
import type { PasetoClaims, PasetoOptions } from "./types";
import { jwkToPasetoPublicKey } from "./utils";

/**
 * Verify a PASETO v4.public token.
 *
 * Reads kid from the footer, looks up the matching key in storage,
 * verifies the token against that key's public half, returns the payload
 * if valid or null otherwise.
 *
 * iss/aud claims are checked against the plugin options (baseURL by default).
 *
 * Context requirement: this helper resolves the active better-auth context
 * via `getCurrentAuthContext()`, which is populated by the request handler
 * chain. Calling `verifyPaseto` outside of a better-auth request scope
 * (e.g. from a standalone script, a background job started without a
 * request, or another framework's handler) will throw because no context
 * is available. Verifiers running outside better-auth should fetch
 * `/paseto-keys` and call a PASETO library directly instead -- that path
 * is what the JWKS-shaped endpoint exists for.
 */
export async function verifyPaseto<T extends PasetoClaims = PasetoClaims>(
  token: string,
  options?: PasetoOptions,
): Promise<(T & Required<Pick<PasetoClaims, "sub" | "aud">>) | null> {
  const ctx = await getCurrentAuthContext();
  try {
    // Quick well-formed check; PASETO v4 tokens start with this prefix.
    if (!token.startsWith("v4.public.")) {
      ctx.context.logger.debug("Token is not v4.public");
      return null;
    }

    // First pass: read the footer to discover the kid without trusting it.
    // The footer is authenticated by the signature so a malicious kid would
    // route us to a key that can't verify the body -- safe by construction.
    const footer = readUntrustedFooter(token);
    const kid = footer?.kid;
    if (!kid) {
      ctx.context.logger.debug("PASETO token missing kid in footer");
      return null;
    }

    const adapter = getPasetoKeysAdapter(ctx.context.adapter, options);
    const keys = await adapter.getAllKeys(ctx as GenericEndpointContext);
    if (!keys || keys.length === 0) {
      ctx.context.logger.debug("No PASETO keys available");
      return null;
    }

    const key = keys.find((k) => k.id === kid);
    if (!key) {
      ctx.context.logger.debug(`No PASETO key found for kid: ${kid}`);
      return null;
    }

    const publicJwk = JSON.parse(key.publicKey);
    const publicKey = jwkToPasetoPublicKey(publicJwk);

    const baseURLOrigin =
      typeof ctx.context.options.baseURL === "string"
        ? ctx.context.options.baseURL
        : undefined;
    const expectedIss = options?.paseto?.issuer ?? baseURLOrigin;
    const expectedAud = options?.paseto?.audience ?? baseURLOrigin;

    const result = await pasetoVerify(publicKey, token);
    const payload = result.payload as PasetoClaims;

    if (expectedIss && payload.iss !== expectedIss) {
      ctx.context.logger.debug(
        `PASETO iss mismatch: got ${payload.iss}, expected ${expectedIss}`,
      );
      return null;
    }
    if (expectedAud) {
      const audValues = Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud];
      const expectedValues = Array.isArray(expectedAud)
        ? expectedAud
        : [expectedAud];
      if (!expectedValues.some((e) => audValues.includes(e))) {
        ctx.context.logger.debug(
          `PASETO aud mismatch: got ${JSON.stringify(payload.aud)}, expected ${JSON.stringify(expectedAud)}`,
        );
        return null;
      }
    }

    if (payload.exp && new Date(payload.exp) < new Date()) {
      ctx.context.logger.debug("PASETO token expired");
      return null;
    }

    if (!payload.sub || !payload.aud) {
      return null;
    }

    return payload as T & Required<Pick<PasetoClaims, "sub" | "aud">>;
  } catch (error) {
    ctx.context.logger.debug("PASETO verification failed", error);
    return null;
  }
}

/**
 * Pull the footer JSON out of a PASETO token without verifying it. Safe
 * because we only use the result to look up the key; if the kid is wrong
 * or tampered, the subsequent signature check fails.
 *
 * PASETO format: v4.<purpose>.<base64url-payload>.<base64url-footer>
 */
function readUntrustedFooter(token: string): { kid?: string } | null {
  const parts = token.split(".");
  if (parts.length < 4) return null;
  try {
    const footerB64 = parts[3]!;
    const pad = "=".repeat((4 - (footerB64.length % 4)) % 4);
    const b64 = (footerB64 + pad).replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64);
    return JSON.parse(json);
  } catch {
    return null;
  }
}
