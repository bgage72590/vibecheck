import { Hono } from "hono";
import { eq } from "drizzle-orm";
import Stripe from "stripe";
import { db } from "../db/client.js";
import { users } from "../db/schema.js";
import { requireAuth, type AuthEnv } from "../middleware/auth.js";

function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY not configured");
  return new Stripe(key, { apiVersion: "2025-02-24.acacia" });
}

const PRICE_ID = process.env.STRIPE_PRO_PRICE_ID ?? "";

const app = new Hono<AuthEnv>();

// Create a Stripe Checkout session for Pro upgrade
app.post("/checkout", requireAuth, async (c) => {
  const userId = c.get("userId");
  const userEmail = c.get("userEmail");

  // Get or create Stripe customer
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  let customerId = user?.stripeCustomerId;

  if (!customerId) {
    const customer = await getStripe().customers.create({
      email: userEmail,
      metadata: { vibecheck_user_id: userId },
    });
    customerId = customer.id;

    await db
      .update(users)
      .set({ stripeCustomerId: customerId, updatedAt: new Date() })
      .where(eq(users.id, userId));
  }

  const session = await getStripe().checkout.sessions.create({
    customer: customerId,
    mode: "subscription",
    line_items: [{ price: PRICE_ID, quantity: 1 }],
    success_url: `${process.env.APP_URL ?? "http://localhost:3847"}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.APP_URL ?? "http://localhost:3847"}/billing/cancel`,
    client_reference_id: userId,
    metadata: { vibecheck_user_id: userId },
  });

  return c.json({ url: session.url });
});

// Get billing portal URL
app.post("/portal", requireAuth, async (c) => {
  const userId = c.get("userId");

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user?.stripeCustomerId) {
    return c.json({ error: "No billing account found" }, 404);
  }

  const session = await getStripe().billingPortal.sessions.create({
    customer: user.stripeCustomerId,
    return_url: process.env.APP_URL ?? "http://localhost:3847",
  });

  return c.json({ url: session.url });
});

export default app;
