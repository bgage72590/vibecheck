import { Hono } from "hono";
import { handle } from "hono/vercel";
import { cors } from "hono/cors";

export const config = {
  runtime: "nodejs",
  maxDuration: 10,
};

const app = new Hono().basePath("/api");

app.use("*", cors({ origin: "*" }));

// Health check
app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
    database: "pending setup",
  });
});

// Stub endpoints — will connect to DB once env vars are set
app.get("/usage/check", (c) => {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ allowed: true, plan: "free", remaining: 3, limit: 3 });
});

app.post("/usage/increment", (c) => {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ ok: true });
});

app.post("/scans", (c) => {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ ok: true }, 201);
});

app.get("/scans", (c) => {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ scans: [] });
});

app.post("/users/sync", (c) => {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ user: { plan: "free" } });
});

app.post("/webhooks/stripe", (c) => {
  if (!c.req.header("stripe-signature")) {
    return c.json({ error: "Missing stripe-signature header" }, 400);
  }
  return c.json({ received: true });
});

export default handle(app);
