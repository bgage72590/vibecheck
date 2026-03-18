import { Hono } from "hono";
import { handle } from "hono/vercel";

export const config = {
  runtime: "nodejs",
  maxDuration: 10,
};

const app = new Hono().basePath("/api");

app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
  });
});

app.get("/usage/check", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ allowed: true, plan: "free", remaining: 3, limit: 3 });
});

app.post("/webhooks/stripe", (c) => {
  if (!c.req.header("stripe-signature")) {
    return c.json({ error: "Missing stripe-signature header" }, 400);
  }
  return c.json({ received: true });
});

app.all("/*", (c) => {
  return c.json({ name: "vibecheck-api", version: "0.1.0", status: "ok" });
});

export default handle(app);
