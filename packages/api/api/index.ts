import { Hono } from "hono";
import { handle } from "hono/vercel";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { eq } from "drizzle-orm";
import { db } from "../src/db/client.js";
import { users } from "../src/db/schema.js";
import { runMigrations } from "../src/db/migrate.js";
import { requireAuth, type AuthEnv } from "../src/middleware/auth.js";
import { rateLimit } from "../src/middleware/rate-limit.js";
import scansRoutes from "../src/routes/scans.js";
import usageRoutes from "../src/routes/usage.js";
import billingRoutes from "../src/routes/billing.js";
import webhooksRoutes from "../src/routes/webhooks.js";

const app = new Hono<AuthEnv>().basePath("/api");

// Global middleware
app.use("*", logger());
app.use(
  "*",
  cors({
    origin: process.env.APP_URL ?? "*",
    allowMethods: ["GET", "POST", "PUT", "DELETE"],
    allowHeaders: ["Authorization", "Content-Type"],
  }),
);

// Rate limiting
app.use("*", rateLimit({ max: 100, windowMs: 60_000 }));
app.use("/billing/*", rateLimit({ max: 10, windowMs: 60_000 }));
app.use("/webhooks/*", rateLimit({ max: 30, windowMs: 60_000 }));

// Health check
app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
  });
});

// User sync
app.post("/users/sync", requireAuth, async (c) => {
  const userId = c.get("userId");
  const userEmail = c.get("userEmail");

  const [existing] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!existing) {
    await db.insert(users).values({ id: userId, email: userEmail });
    return c.json({ user: { id: userId, email: userEmail, plan: "free" } }, 201);
  }

  return c.json({
    user: { id: existing.id, email: existing.email, plan: existing.plan },
  });
});

// User info
app.get("/users/me", requireAuth, async (c) => {
  const userId = c.get("userId");
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user) return c.json({ error: "User not found" }, 404);

  return c.json({
    user: { id: user.id, email: user.email, plan: user.plan, createdAt: user.createdAt },
  });
});

// Mount route groups
app.route("/scans", scansRoutes);
app.route("/usage", usageRoutes);
app.route("/billing", billingRoutes);
app.route("/webhooks", webhooksRoutes);

// Run migrations on cold start
let migrated = false;
app.use("*", async (_c, next) => {
  if (!migrated) {
    await runMigrations();
    migrated = true;
  }
  await next();
});

export default handle(app);
