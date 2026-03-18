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

  if (typeof directory !== "string" || directory.length > 500) return c.json({ error: "Invalid directory" }, 400);
  if (typeof filesScanned !== "number" || filesScanned < 0 || filesScanned > 100000) return c.json({ error: "Invalid filesScanned" }, 400);
  if (!Array.isArray(findings) || findings.length > 10000) return c.json({ error: "Invalid findings" }, 400);
  if (typeof duration !== "number" || duration < 0) return c.json({ error: "Invalid duration" }, 400);

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
  const limit = Math.min(Math.max(1, parseInt(c.req.query("limit") ?? "20", 10) || 20), 100);
  const offset = Math.max(0, parseInt(c.req.query("offset") ?? "0", 10) || 0);

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

  if (!scan || scan.userId !== userId) {
    return c.json({ error: "Scan not found" }, 404);
  }

  let parsedFindings = [];
  try {
    parsedFindings = scan.findings ? JSON.parse(scan.findings as string) : [];
  } catch {
    parsedFindings = [];
  }

  return c.json({
    scan: {
      ...scan,
      findings: parsedFindings,
    },
  });
});

export default app;
