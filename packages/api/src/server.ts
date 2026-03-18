import { Hono } from "hono";
import { cors } from "hono/cors";
import { bodyLimit } from "hono/body-limit";
import { logger } from "hono/logger";
import { eq } from "drizzle-orm";
import { db } from "./db/client.js";
import { users } from "./db/schema.js";
import { runMigrations } from "./db/migrate.js";
import { requireAuth, type AuthEnv } from "./middleware/auth.js";
import { rateLimit } from "./middleware/rate-limit.js";
import scansRoutes from "./routes/scans.js";
import usageRoutes from "./routes/usage.js";
import billingRoutes from "./routes/billing.js";
import webhooksRoutes from "./routes/webhooks.js";

const app = new Hono<AuthEnv>();

// Global middleware
app.use("*", logger());
app.use(
  "/api/*",
  cors({
    origin: process.env.APP_URL || "http://localhost:3847",
    allowMethods: ["GET", "POST", "PUT", "DELETE"],
    allowHeaders: ["Authorization", "Content-Type"],
  }),
);

// Body size limit: 5MB max for API routes
app.use("/api/*", bodyLimit({ maxSize: 5 * 1024 * 1024 })); // 5MB max

// Rate limiting: 100 requests per minute per IP for API routes
app.use("/api/*", rateLimit({ max: 100, windowMs: 60_000 }));

// Stricter rate limit on auth-sensitive endpoints
app.use("/api/billing/*", rateLimit({ max: 10, windowMs: 60_000 }));
app.use("/api/webhooks/*", rateLimit({ max: 30, windowMs: 60_000 }));

// Health check
app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
  });
});

// User sync endpoint — called after CLI login to ensure user exists in DB
app.post("/api/users/sync", requireAuth, async (c) => {
  const userId = c.get("userId");
  const userEmail = c.get("userEmail");

  const [existing] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!existing) {
    await db.insert(users).values({
      id: userId,
      email: userEmail,
    });
    return c.json({ user: { id: userId, email: userEmail, plan: "free" } }, 201);
  }

  return c.json({
    user: {
      id: existing.id,
      email: existing.email,
      plan: existing.plan,
    },
  });
});

// Get current user info
app.get("/api/users/me", requireAuth, async (c) => {
  const userId = c.get("userId");

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      plan: user.plan,
      createdAt: user.createdAt,
    },
  });
});

// Mount route groups
app.route("/api/scans", scansRoutes);
app.route("/api/usage", usageRoutes);
app.route("/api/billing", billingRoutes);
app.route("/api/webhooks", webhooksRoutes);

// Start server
import { serve } from "@hono/node-server";

const PORT = parseInt(process.env.PORT ?? "3456");

async function start() {
  const requiredEnvVars = ["CLERK_SECRET_KEY", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"];
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      console.warn(`WARNING: ${envVar} is not set`);
    }
  }

  await runMigrations();
  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`VibeCheck API running at http://localhost:${PORT}`);
  });
}

start();
