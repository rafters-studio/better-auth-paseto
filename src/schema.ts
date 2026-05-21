import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

/**
 * Table for the plugin's key set. Same field shape as better-auth's JWT
 * plugin uses for its `jwks` table, with a different table name so the
 * two plugins can coexist during migration.
 */
export const schema = {
  paseto_keys: {
    fields: {
      publicKey: {
        type: "string",
        required: true,
      },
      privateKey: {
        type: "string",
        required: true,
      },
      createdAt: {
        type: "date",
        required: true,
      },
      expiresAt: {
        type: "date",
        required: false,
      },
    },
  },
} satisfies BetterAuthPluginDBSchema;
