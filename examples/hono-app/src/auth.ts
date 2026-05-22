import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { paseto } from "@rafters/better-auth-paseto";

// In-memory DB. Every model the system uses needs a slot pre-allocated.
const db: Record<string, any[]> = {
  user: [],
  session: [],
  account: [],
  verification: [],
  paseto_keys: [],
};

// Vite-based tools (vitest, astro, sveltekit, ...) set
// process.env.BASE_URL = "/" by default. `??` does not fall back on
// "/", so an unsanitised read produces a malformed base URL. Treat
// "/" and empty as unset.
const envBase = process.env.BASE_URL;
const baseURL = !envBase || envBase === "/" ? "http://localhost:3000" : envBase;

export const auth = betterAuth({
  baseURL,
  secret:
    process.env.BETTER_AUTH_SECRET ??
    "dev-secret-replace-me-with-something-32-chars-or-more",
  database: memoryAdapter(db),
  emailAndPassword: { enabled: true },
  plugins: [
    paseto({
      paseto: {
        issuer: baseURL,
        audience: baseURL,
        expirationTime: "15m",
      },
    }),
  ],
});
