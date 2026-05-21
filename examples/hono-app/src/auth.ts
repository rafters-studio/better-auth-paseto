import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { paseto } from "@rafters-studio/better-auth-paseto";

// In-memory DB. Every model the system uses needs a slot pre-allocated.
const db: Record<string, any[]> = {
  user: [],
  session: [],
  account: [],
  verification: [],
  paseto_keys: [],
};

export const auth = betterAuth({
  baseURL: process.env.BASE_URL ?? "http://localhost:3000",
  secret:
    process.env.BETTER_AUTH_SECRET ??
    "dev-secret-replace-me-with-something-32-chars-or-more",
  database: memoryAdapter(db),
  emailAndPassword: { enabled: true },
  plugins: [
    paseto({
      paseto: {
        issuer: process.env.BASE_URL ?? "http://localhost:3000",
        audience: process.env.BASE_URL ?? "http://localhost:3000",
        expirationTime: "15m",
      },
    }),
  ],
});
