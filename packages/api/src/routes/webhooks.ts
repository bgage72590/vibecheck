import { Hono } from "hono";
import { eq } from "drizzle-orm";
import Stripe from "stripe";
import { db } from "../db/client.js";
import { users } from "../db/schema.js";

function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY not configured");
  return new Stripe(key, { apiVersion: "2025-02-24.acacia" });
}

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET ?? "";

const app = new Hono();

// Stripe webhook endpoint
app.post("/stripe", async (c) => {
  const signature = c.req.header("stripe-signature");
  if (!signature) {
    return c.json({ error: "Missing stripe-signature header" }, 400);
  }

  const body = await c.req.text();

  if (!WEBHOOK_SECRET) {
    console.error("STRIPE_WEBHOOK_SECRET not configured");
    return c.json({ error: "Webhook not configured" }, 500);
  }

  let event: Stripe.Event;
  try {
    event = getStripe().webhooks.constructEvent(body, signature, WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return c.json({ error: "Invalid signature" }, 400);
  }

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.client_reference_id;
      if (userId) {
        await db
          .update(users)
          .set({
            plan: "pro",
            stripeSubscriptionId: session.subscription as string,
            updatedAt: new Date(),
          })
          .where(eq(users.id, userId));
        console.log(`User ${userId} upgraded to Pro`);
      }
      break;
    }

    case "customer.subscription.deleted": {
      const subscription = event.data.object as Stripe.Subscription;
      const customerId = subscription.customer as string;

      // Find user by Stripe customer ID
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.stripeCustomerId, customerId))
        .limit(1);

      if (user) {
        await db
          .update(users)
          .set({
            plan: "free",
            stripeSubscriptionId: null,
            updatedAt: new Date(),
          })
          .where(eq(users.id, user.id));
        console.log(`User ${user.id} downgraded to Free`);
      }
      break;
    }

    case "customer.subscription.updated": {
      const subscription = event.data.object as Stripe.Subscription;
      const customerId = subscription.customer as string;

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.stripeCustomerId, customerId))
        .limit(1);

      if (user) {
        const isActive = subscription.status === "active" || subscription.status === "trialing";
        await db
          .update(users)
          .set({
            plan: isActive ? "pro" : "free",
            updatedAt: new Date(),
          })
          .where(eq(users.id, user.id));
      }
      break;
    }

    default:
      // Unhandled event type
      break;
  }

  return c.json({ received: true });
});

export default app;
