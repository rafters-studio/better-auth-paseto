import type {
  BetterAuthOptions,
  GenericEndpointContext,
} from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import type { PasetoKey, PasetoOptions } from "./types";

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
      const keys = await adapter.findMany<PasetoKey>({
        model: "paseto_keys",
      });
      return keys?.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
      )[0];
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
        data: {
          ...key,
          createdAt: new Date(),
        },
      });
    },
  };
};
