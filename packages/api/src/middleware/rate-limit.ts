import { createMiddleware } from "hono/factory";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const store = new Map<string, RateLimitEntry>();

// Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now > entry.resetAt) store.delete(key);
  }
}, 5 * 60 * 1000);

/**
 * Simple in-memory rate limiter.
 * For production with multiple instances, swap for Redis-backed.
 */
export function rateLimit(opts: {
  /** Max requests per window */
  max: number;
  /** Window in milliseconds */
  windowMs: number;
  /** Key function — defaults to IP address */
  keyFn?: (c: { req: { header: (name: string) => string | undefined } }) => string;
}) {
  const { max, windowMs, keyFn } = opts;

  return createMiddleware(async (c, next) => {
    const key = keyFn
      ? keyFn(c)
      : c.req.header("x-forwarded-for") ?? c.req.header("x-real-ip") ?? "unknown";

    const now = Date.now();
    let entry = store.get(key);

    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      store.set(key, entry);
    }

    entry.count++;

    // Set rate limit headers
    c.header("X-RateLimit-Limit", max.toString());
    c.header("X-RateLimit-Remaining", Math.max(0, max - entry.count).toString());
    c.header("X-RateLimit-Reset", Math.ceil(entry.resetAt / 1000).toString());

    if (entry.count > max) {
      c.header("Retry-After", Math.ceil((entry.resetAt - now) / 1000).toString());
      return c.json(
        {
          error: "Too many requests",
          retryAfter: Math.ceil((entry.resetAt - now) / 1000),
        },
        429,
      );
    }

    await next();
  });
}
