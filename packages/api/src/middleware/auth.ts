import { createMiddleware } from "hono/factory";
import { createClerkClient } from "@clerk/backend";
import type { Context } from "hono";

const clerk = createClerkClient({
  secretKey: process.env.CLERK_SECRET_KEY,
});

export type AuthEnv = {
  Variables: {
    userId: string;
    userEmail: string;
  };
};

/**
 * Middleware that verifies the Clerk JWT from the Authorization header.
 * Sets userId and userEmail on the context.
 */
export const requireAuth = createMiddleware<AuthEnv>(async (c, next) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await clerk.verifyToken(token);
    c.set("userId", payload.sub);
    c.set("userEmail", (payload as Record<string, unknown>).email as string ?? "");
    await next();
  } catch {
    return c.json({ error: "Invalid or expired token" }, 401);
  }
});

/**
 * Optional auth — sets userId if token is present, but doesn't block.
 */
export const optionalAuth = createMiddleware<AuthEnv>(async (c, next) => {
  const authHeader = c.req.header("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    try {
      const payload = await clerk.verifyToken(token);
      c.set("userId", payload.sub);
      c.set("userEmail", (payload as Record<string, unknown>).email as string ?? "");
    } catch {
      // Token invalid — continue as unauthenticated
    }
  }
  await next();
});
