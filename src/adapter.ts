import type {
  BetterAuthOptions,
  GenericEndpointContext,
} from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
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
    createKey: async (
      ctx: GenericEndpointContext,
      key: Omit<PasetoKey, "id">,
    ) => {
      if (options?.adapter?.createKey) {
        return await options.adapter.createKey(key, ctx);
      }
      return await adapter.create<Omit<PasetoKey, "id">, PasetoKey>({
        model: "paseto_keys",
        data: key,
      });
    },
  };
};
