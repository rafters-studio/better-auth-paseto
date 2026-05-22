import { Hono } from "hono";
import { auth } from "./auth";

/**
 * Build the Hono app. Exported separately from the server bootstrap
 * (src/index.ts) so the integration tests can call `app.fetch` directly
 * without spinning up a real socket.
 */
export const app = new Hono();

// Mount better-auth under /api/auth/*. The paseto plugin's endpoints
// (/paseto-keys, /token, /sign-paseto, /verify-paseto) become
// /api/auth/paseto-keys, /api/auth/token, etc.
app.all("/api/auth/*", async (c) => {
  return auth.handler(c.req.raw);
});

// A protected example route that reads the session and echoes it back.
// Try hitting it without auth first (you'll get null), then with the
// session cookie set by sign-in.
app.get("/me", async (c) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "not signed in" }, 401);
  return c.json({ user: session.user });
});

// Hello-world health check.
app.get("/", (c) =>
  c.text(
    "better-auth-paseto example Hono app. See README.md for the full curl walkthrough.\n",
  ),
);
