import type { GenericEndpointContext } from "@better-auth/core";
import { getCurrentAuthContext } from "@better-auth/core/context";
import { verify as pasetoVerify } from "paseto-ts/v4";
import { getPasetoKeysAdapter } from "./adapter";
import type {
  PasetoClaims,
  PasetoOptions,
  PasetoVerifyErrorKind,
  PasetoVerifyResult,
} from "./types";
import { jwkToPasetoPublicKey } from "./utils";

const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/**
 * Verify a PASETO v4.public token and return a structured success/failure.
 *
 * Reads kid from the footer, looks up the matching key in storage,
 * verifies the token against that key's public half, checks the claim
 * set against the configured issuer/audience and the current clock,
 * and returns either `{ ok: true, payload }` or `{ ok: false, error }`
 * with a discriminated `kind` for branching.
 *
 * The default clock skew of 60s applies symmetrically to `exp` (allow
 * tokens up to 60s past) and `nbf` (allow tokens whose `nbf` is up to
 * 60s in the future). Set `options.paseto.clockSkew = 0` for strict
 * comparison.
 *
 * Context requirement: this helper resolves the active better-auth
 * context via `getCurrentAuthContext()`, which is populated by the
 * request handler chain. Calling it outside a better-auth request
 * scope throws because no context is available. For verification
 * outside a better-auth request, fetch `/paseto-keys` and call a
 * PASETO library directly -- that path is what the JWKS-shaped endpoint
 * exists for.
 */
export async function verifyPasetoWithReason<
  T extends PasetoClaims = PasetoClaims,
>(token: string, options?: PasetoOptions): Promise<PasetoVerifyResult<T>> {
  const ctx = await getCurrentAuthContext();

  if (!token.startsWith("v4.public.")) {
    return fail("malformed", "token is not v4.public");
  }

  const footer = readUntrustedFooter(token);
  const kid = footer?.kid;
  if (!kid) {
    return fail("missing_kid", "token footer is missing kid");
  }

  const adapter = getPasetoKeysAdapter(ctx.context.adapter, options);
  const keys = await adapter.getAllKeys(ctx as GenericEndpointContext);
  if (!keys || keys.length === 0) {
    return fail("unknown_kid", "no PASETO keys available");
  }

  const key = keys.find((k) => k.id === kid);
  if (!key) {
    return fail("unknown_kid", `no PASETO key for kid: ${kid}`);
  }

  const publicJwk = JSON.parse(key.publicKey);
  const publicKey = jwkToPasetoPublicKey(publicJwk);

  let result: { payload: unknown };
  try {
    // Pass validatePayload: false so paseto-ts only validates the
    // signature and not the claim set. The plugin owns claim validation
    // (iss/aud/nbf/exp) below, including clock-skew tolerance that
    // paseto-ts's built-in checks deliberately do not support.
    result = await pasetoVerify(publicKey, token, { validatePayload: false });
  } catch (err) {
    return fail(
      "invalid_signature",
      err instanceof Error ? err.message : String(err),
    );
  }
  const payload = result.payload as PasetoClaims;

  const baseURLOrigin =
    typeof ctx.context.options.baseURL === "string"
      ? ctx.context.options.baseURL
      : undefined;
  const expectedIss = options?.paseto?.issuer ?? baseURLOrigin;
  const expectedAud = options?.paseto?.audience ?? baseURLOrigin;

  if (expectedIss && payload.iss !== expectedIss) {
    return fail(
      "wrong_issuer",
      `expected ${expectedIss}, got ${String(payload.iss)}`,
    );
  }
  if (expectedAud) {
    const audValues = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const expectedValues = Array.isArray(expectedAud)
      ? expectedAud
      : [expectedAud];
    if (!expectedValues.some((e) => audValues.includes(e))) {
      return fail(
        "wrong_audience",
        `expected ${JSON.stringify(expectedAud)}, got ${JSON.stringify(payload.aud)}`,
      );
    }
  }

  const skewSec = options?.paseto?.clockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const skewMs = skewSec * 1000;
  const now = Date.now();

  if (payload.nbf) {
    const nbfMs = new Date(payload.nbf).getTime();
    if (Number.isFinite(nbfMs) && nbfMs - skewMs > now) {
      return fail("not_yet_valid", `nbf ${payload.nbf} is in the future`);
    }
  }

  if (payload.exp) {
    const expMs = new Date(payload.exp).getTime();
    if (Number.isFinite(expMs) && expMs + skewMs < now) {
      return fail("expired", `exp ${payload.exp} is in the past`);
    }
  }

  if (!payload.sub || !payload.aud) {
    return fail("malformed", "token missing required claim (sub or aud)");
  }

  return {
    ok: true,
    payload: payload as T & Required<Pick<PasetoClaims, "sub" | "aud">>,
  };
}

/**
 * Verify a PASETO v4.public token. Returns the payload if valid or null
 * otherwise. The HTTP `/verify-paseto` endpoint uses this signature so the
 * wire response never leaks a rejection reason.
 *
 * Server-side callers that want to log or branch on the rejection reason
 * should use `verifyPasetoWithReason` instead, which returns a structured
 * `{ ok, payload | error }` result.
 */
export async function verifyPaseto<T extends PasetoClaims = PasetoClaims>(
  token: string,
  options?: PasetoOptions,
): Promise<(T & Required<Pick<PasetoClaims, "sub" | "aud">>) | null> {
  const result = await verifyPasetoWithReason<T>(token, options);
  if (result.ok) return result.payload;
  // Log the structured reason at debug; same level the JWT plugin uses,
  // and consistent with the prior null-only behaviour from the caller's
  // perspective.
  try {
    const ctx = await getCurrentAuthContext();
    ctx.context.logger.debug(
      `PASETO verify failed: ${result.error.kind} -- ${result.error.message}`,
    );
  } catch {
    // No-op if the context is unavailable; verifyPasetoWithReason already
    // surfaced the same diagnostic via its return value.
  }
  return null;
}

function fail(
  kind: PasetoVerifyErrorKind,
  message: string,
): PasetoVerifyResult<never> {
  return { ok: false, error: { kind, message } };
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
