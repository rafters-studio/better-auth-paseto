import type {
  BetterAuthOptions,
  GenericEndpointContext,
} from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { BetterAuthError } from "@better-auth/core/error";
import type { PasetoKey, PasetoOptions } from "./types";

/**
 * Adapter facade over either the better-auth DB adapter or a caller-supplied
 * override (KMS, secrets store, etc.).
 *
 * Naming bridge: the override hook is named `getKeys` in `PasetoOptions`
 * (the public API name) but is exposed internally as `getAllKeys` to make
 * the call sites read clearly alongside `getLatestKey`. The override is
 * the source of truth when present; the internal adapter handles ordering
 * and pagination natively when it is not.
 *
 * createKey arg-order swap: the public override takes `(data, ctx)` so
 * the data is the focal argument, matching better-auth plugin convention.
 * The internal call uses `(ctx, key)` to match the broader adapter family.
 * The wrapper handles the swap.
 */
export const getPasetoKeysAdapter = (
  adapter: DBAdapter<BetterAuthOptions>,
  options?: PasetoOptions,
) => {
  return {
    getAllKeys: async (ctx: GenericEndpointContext) => {
      if (options?.adapter?.getKeys) {
        return await options.adapter.getKeys(ctx);
      }
      return await adapter.findMany<PasetoKey>({
        model: "paseto_keys",
      });
    },
    getLatestKey: async (ctx: GenericEndpointContext) => {
      if (options?.adapter?.getKeys) {
        const keys = await options.adapter.getKeys(ctx);
        return keys?.sort(
          (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
        )[0];
      }
      // Push the sort + limit down to the adapter. Sorting in JS scaled
      // linearly with the size of the key set, which grows with rotation
      // frequency multiplied by grace period.
      const keys = await adapter.findMany<PasetoKey>({
        model: "paseto_keys",
        sortBy: { field: "createdAt", direction: "desc" },
        limit: 1,
      });
      return keys?.[0];
    },
    /**
     * Create a key row. `requestCtx` is required only when a user
     * adapter override is set -- the override may need request-scoped
     * context to talk to a KMS or secrets store. The default DB path
     * does not use the request context and accepts undefined, which
     * lets the plugin init hook seed the first key without faking a
     * request.
     */
    createKey: async (
      key: Omit<PasetoKey, "id">,
      requestCtx?: GenericEndpointContext,
    ) => {
      if (options?.adapter?.createKey) {
        if (!requestCtx) {
          throw new BetterAuthError(
            "options.adapter.createKey requires a request context. " +
              "When a custom adapter is configured, the first key must be " +
              "seeded out of band (init cannot synthesise a request).",
          );
        }
        return await options.adapter.createKey(key, requestCtx);
      }
      return await adapter.create<Omit<PasetoKey, "id">, PasetoKey>({
        model: "paseto_keys",
        data: key,
      });
    },
  };
};
