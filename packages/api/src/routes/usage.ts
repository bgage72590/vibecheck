import { Hono } from "hono";
import { eq, and } from "drizzle-orm";
import { db } from "../db/client.js";
import { dailyUsage, users } from "../db/schema.js";
import { requireAuth, type AuthEnv } from "../middleware/auth.js";

const FREE_DAILY_LIMIT = 3;

const app = new Hono<AuthEnv>();

function todayDate(): string {
  return new Date().toISOString().split("T")[0];
}

// Check if user can scan (returns remaining scans)
app.get("/check", requireAuth, async (c) => {
  const userId = c.get("userId");
  const today = todayDate();

  // Get user plan
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  // Pro users have unlimited scans
  if (user?.plan === "pro") {
    return c.json({
      allowed: true,
      plan: "pro",
      remaining: -1, // unlimited
      limit: -1,
    });
  }

  // Check daily usage for free users
  const [usage] = await db
    .select()
    .from(dailyUsage)
    .where(and(eq(dailyUsage.userId, userId), eq(dailyUsage.date, today)))
    .limit(1);

  const used = usage?.scanCount ?? 0;
  const remaining = Math.max(0, FREE_DAILY_LIMIT - used);

  return c.json({
    allowed: remaining > 0,
    plan: "free",
    remaining,
    limit: FREE_DAILY_LIMIT,
    used,
  });
});

// Increment usage (called after a scan completes)
app.post("/increment", requireAuth, async (c) => {
  const userId = c.get("userId");
  const today = todayDate();

  // Check user plan
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  // Pro users don't need usage tracking
  if (user?.plan === "pro") {
    return c.json({ ok: true, plan: "pro" });
  }

  // Upsert daily usage
  const [existing] = await db
    .select()
    .from(dailyUsage)
    .where(and(eq(dailyUsage.userId, userId), eq(dailyUsage.date, today)))
    .limit(1);

  if (existing) {
    if (existing.scanCount >= FREE_DAILY_LIMIT) {
      return c.json(
        {
          error: "Daily scan limit reached",
          plan: "free",
          limit: FREE_DAILY_LIMIT,
          upgradeUrl: "/api/billing/checkout",
        },
        429,
      );
    }

    await db
      .update(dailyUsage)
      .set({ scanCount: existing.scanCount + 1 })
      .where(eq(dailyUsage.id, existing.id));
  } else {
    await db.insert(dailyUsage).values({
      userId,
      date: today,
      scanCount: 1,
    });
  }

  return c.json({ ok: true });
});

// Get usage stats
app.get("/stats", requireAuth, async (c) => {
  const userId = c.get("userId");

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  const today = todayDate();
  const [todayUsage] = await db
    .select()
    .from(dailyUsage)
    .where(and(eq(dailyUsage.userId, userId), eq(dailyUsage.date, today)))
    .limit(1);

  return c.json({
    plan: user?.plan ?? "free",
    todayScans: todayUsage?.scanCount ?? 0,
    dailyLimit: user?.plan === "pro" ? -1 : FREE_DAILY_LIMIT,
  });
});

export default app;
