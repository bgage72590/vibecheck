import { Hono } from "hono";
import { eq, desc } from "drizzle-orm";
import { db } from "../db/client.js";
import { scans, users } from "../db/schema.js";
import { requireAuth, type AuthEnv } from "../middleware/auth.js";

const app = new Hono<AuthEnv>();

// Save scan results
app.post("/", requireAuth, async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json();

  const { directory, filesScanned, findings, duration } = body;

  if (!directory || filesScanned === undefined || !findings || !duration) {
    return c.json({ error: "Missing required fields" }, 400);
  }

  const criticalCount = findings.filter((f: { severity: string }) => f.severity === "critical").length;
  const highCount = findings.filter((f: { severity: string }) => f.severity === "high").length;
  const mediumCount = findings.filter((f: { severity: string }) => f.severity === "medium").length;
  const lowCount = findings.filter((f: { severity: string }) => f.severity === "low").length;

  const [scan] = await db
    .insert(scans)
    .values({
      userId,
      directory,
      filesScanned,
      findingsCount: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      duration,
      findings: JSON.stringify(findings),
    })
    .returning();

  return c.json({ scan }, 201);
});

// Get scan history
app.get("/", requireAuth, async (c) => {
  const userId = c.get("userId");
  const limit = parseInt(c.req.query("limit") ?? "20");
  const offset = parseInt(c.req.query("offset") ?? "0");

  const results = await db
    .select({
      id: scans.id,
      directory: scans.directory,
      filesScanned: scans.filesScanned,
      findingsCount: scans.findingsCount,
      criticalCount: scans.criticalCount,
      highCount: scans.highCount,
      mediumCount: scans.mediumCount,
      lowCount: scans.lowCount,
      duration: scans.duration,
      createdAt: scans.createdAt,
    })
    .from(scans)
    .where(eq(scans.userId, userId))
    .orderBy(desc(scans.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json({ scans: results });
});

// Get a specific scan with full findings
app.get("/:id", requireAuth, async (c) => {
  const userId = c.get("userId");
  const scanId = c.req.param("id");

  const [scan] = await db
    .select()
    .from(scans)
    .where(eq(scans.id, scanId))
    .limit(1);

  if (!scan) {
    return c.json({ error: "Scan not found" }, 404);
  }

  if (scan.userId !== userId) {
    return c.json({ error: "Not authorized" }, 403);
  }

  return c.json({
    scan: {
      ...scan,
      findings: scan.findings ? JSON.parse(scan.findings as string) : [],
    },
  });
});

export default app;
