import { Hono } from "hono";
import { handle } from "hono/vercel";
import { cors } from "hono/cors";

export const config = {
  runtime: "nodejs",
};

const app = new Hono().basePath("/api");

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "PUT", "DELETE"],
    allowHeaders: ["Authorization", "Content-Type"],
  }),
);

// Health check
app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
  });
});

// Usage check (stub — full implementation requires Turso DB env vars)
app.get("/usage/check", (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ allowed: true, plan: "free", remaining: 3, limit: 3 });
});

// Scans endpoint (stub)
app.post("/scans", (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ ok: true });
});

// Webhooks (stub)
app.post("/webhooks/stripe", (c) => {
  const signature = c.req.header("stripe-signature");
  if (!signature) {
    return c.json({ error: "Missing stripe-signature header" }, 400);
  }
  return c.json({ received: true });
});

// Catch-all for unmatched routes
app.all("/*", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
    note: "Use /api for the health check endpoint",
  });
});

export default handle(app);
