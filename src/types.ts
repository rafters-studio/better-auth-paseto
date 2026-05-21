import type { Awaitable, GenericEndpointContext } from "@better-auth/core";
import type { InferOptionSchema, Session, User } from "better-auth";
import type { schema } from "./schema";

/**
 * PASETO claims set. Mirrors the JWT registered claims because PASETO v4
 * inherits them verbatim; only the wire format changes.
 *
 * @see https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md
 */
export interface PasetoClaims {
  /** Issuer. */
  iss?: string;
  /** Subject. */
  sub?: string;
  /** Audience. */
  aud?: string | string[];
  /** Token ID. */
  jti?: string;
  /** Not Before, ISO-8601 string. */
  nbf?: string;
  /** Expiration Time, ISO-8601 string. */
  exp?: string;
  /** Issued At, ISO-8601 string. */
  iat?: string;
  /** Any other claim. */
  [propName: string]: unknown;
}

export interface PasetoOptions {
  keys?: {
    /**
     * Remote URL serving the public-key set (JWKS-shaped).
     * When set, the plugin verifies tokens against this remote set rather
     * than the local database, and the local /paseto-keys endpoint is disabled.
     */
    remoteUrl?: string;
    /**
     * Encrypt the private key at rest using the better-auth secret.
     * Defaults to true. Set to false only if your DB-at-rest encryption
     * already covers the private-key column.
     */
    disablePrivateKeyEncryption?: boolean;
    /**
     * Rotate keys every N seconds. New tokens are signed by the latest key;
     * the public-key endpoint continues to serve older keys until
     * gracePeriod elapses.
     */
    rotationInterval?: number;
    /**
     * Seconds an expired key remains in the public-key set so in-flight
     * tokens can still be verified. Default: 30 days.
     */
    gracePeriod?: number;
    /**
     * Path of the public-key endpoint. Default: "/paseto-keys".
     */
    keysPath?: string;
  };

  paseto?: {
    /** Token issuer claim. Defaults to the better-auth baseURL origin. */
    issuer?: string;
    /** Token audience claim. Defaults to the better-auth baseURL origin. */
    audience?: string | string[];
    /** Expiration. Number of seconds, Date, or duration string (e.g. "15m"). */
    expirationTime?: number | string | Date;
    /** Custom payload builder. Called per session-derived token mint. */
    definePayload?: (session: {
      user: User & Record<string, any>;
      session: Session & Record<string, any>;
    }) => Awaitable<Record<string, any> | undefined>;
    /** Custom subject extractor. Defaults to user.id. */
    getSubject?: (session: {
      user: User & Record<string, any>;
      session: Session & Record<string, any>;
    }) => Awaitable<string | undefined>;
    /**
     * Replace the in-process signer with a remote one (KMS, HSM, etc).
     * When set, options.keys.remoteUrl must also be set so verifiers can
     * find the matching public key.
     */
    sign?: (payload: PasetoClaims) => Awaitable<string>;
  };

  /**
   * Skip the `set-auth-paseto` response header on /get-session.
   * Default: false.
   */
  disableSettingHeader?: boolean;

  schema?: InferOptionSchema<typeof schema>;

  /**
   * Override the default DB adapter. Useful when your key storage is not
   * a better-auth-managed table (e.g. cloud KMS, external secrets store).
   */
  adapter?: {
    getKeys?: (
      ctx: GenericEndpointContext,
    ) => Promise<PasetoKey[] | null | undefined>;
    createKey?: (
      data: Omit<PasetoKey, "id">,
      ctx: GenericEndpointContext,
    ) => Promise<PasetoKey>;
  };
}

/**
 * One PASETO key record in the database.
 *
 * publicKey and privateKey are stored as JWK JSON strings ({kty: "OKP",
 * crv: "Ed25519", x: <pub>, d: <priv>}). This is the same shape better-auth's
 * JWT plugin uses for Ed25519 keys, which makes the /paseto-keys endpoint
 * JWKS-compatible for free.
 */
export interface PasetoKey {
  id: string;
  publicKey: string;
  privateKey: string;
  createdAt: Date;
  expiresAt?: Date;
}
