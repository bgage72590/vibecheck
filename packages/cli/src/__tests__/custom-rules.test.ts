import { describe, it, expect } from "vitest";
import { runCustomRules } from "../scanners/custom-rules.js";

// Helper: run rules on a string, return findings for a specific rule
function scan(content: string, filePath = "test.js") {
  return runCustomRules(content, filePath);
}

function findByRule(content: string, ruleId: string, filePath = "test.js") {
  return scan(content, filePath).filter((f) => f.rule === ruleId);
}

// ─── VC001: Hardcoded API Key or Secret ───────────────────

describe("VC001 — Hardcoded Secrets", () => {
  it("detects hardcoded secret tokens", () => {
    const findings = findByRule(
      `const api_secret = "xK9mPqR2nT5vW8yB3dF6hJ0lN4sU7aE9cG1iM3o";`,
      "VC001",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("detects OpenAI keys", () => {
    const findings = findByRule(
      `const api_key = "sk-FAKE-not-real-key-for-testing-only-1234567890abcdef";`,
      "VC001",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects AWS access keys", () => {
    const findings = findByRule(`const key = "AKIAIOSFODNN7EXAMPLE";`, "VC001");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects database URLs with credentials", () => {
    const findings = findByRule(
      `const db = "postgres://admin:secretpass@db.example.com:5432/myapp";`,
      "VC001",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects private keys", () => {
    const findings = findByRule(
      `const cert = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";`,
      "VC001",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("ignores .env.example files", () => {
    const findings = findByRule(
      `API_KEY=your-key-here`,
      "VC001",
      "config/.env.example",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores short non-secret strings", () => {
    const findings = findByRule(
      `const name = "hello world";`,
      "VC001",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC002: Exposed .env File ─────────────────────────────

describe("VC002 — Exposed .env File", () => {
  it("flags .env files with secrets", () => {
    const findings = findByRule(
      `DATABASE_URL=postgres://admin:pass@db:5432/app\nSTRIPE_SECRET_KEY=sk_live_123`,
      "VC002",
      ".env",
    );
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
  });

  it("flags .env.local files", () => {
    const findings = findByRule(
      `API_KEY=secret123\nDATABASE_PASSWORD=hunter2`,
      "VC002",
      ".env.local",
    );
    expect(findings.length).toBe(1);
  });

  it("ignores .env.example", () => {
    const findings = findByRule(
      `DATABASE_URL=\nAPI_KEY=`,
      "VC002",
      ".env.example",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores .env without secrets", () => {
    const findings = findByRule(
      `NODE_ENV=production\nPORT=3000`,
      "VC002",
      ".env",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC003: Missing Auth Middleware ────────────────────────

describe("VC003 — Missing Auth on API Routes", () => {
  it("flags Express routes without auth", () => {
    const findings = findByRule(
      `app.get("/api/users", async (req, res) => { res.json([]); });`,
      "VC003",
      "routes/users.js",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
  });

  it("flags Next.js API routes without auth", () => {
    const findings = findByRule(
      `export async function GET(req) { return Response.json([]); }`,
      "VC003",
      "app/api/users/route.ts",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("passes when auth middleware is present", () => {
    const findings = findByRule(
      `import { getServerSession } from "next-auth";\napp.get("/api/users", async (req, res) => { const session = await getServerSession(); });`,
      "VC003",
      "routes/users.js",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores non-API files", () => {
    const findings = findByRule(
      `app.get("/api/users", async (req, res) => {});`,
      "VC003",
      "components/Button.tsx",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC004: Supabase RLS Bypass ───────────────────────────

describe("VC004 — Supabase RLS Bypass", () => {
  it("flags .rpc() calls", () => {
    const findings = findByRule(
      `import { createClient } from "@supabase/supabase-js";\nconst supabase = createClient(url, key);\nconst { data } = await supabase.from("users").select("*");\nawait supabase.rpc("delete_user", { id: 1 });`,
      "VC004",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("flags service_role in client-side code", () => {
    const findings = findByRule(
      `"use client";\nconst supabase_service_role_key = "eyJ...";`,
      "VC004",
      "Dashboard.tsx",
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ─── VC005: Unprotected Stripe Webhook ────────────────────

describe("VC005 — Unprotected Stripe Webhook", () => {
  it("flags webhook routes without verification", () => {
    const findings = findByRule(
      `app.post("/api/webhooks/stripe", async (req, res) => {\n  const event = req.body;\n  res.json({ ok: true });\n});`,
      "VC005",
      "routes/webhook.js",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("passes when constructEvent is used", () => {
    const findings = findByRule(
      `app.post("/webhook", async (req, res) => {\n  const event = stripe.webhooks.constructEvent(body, sig, secret);\n});`,
      "VC005",
      "routes/webhook.js",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores non-webhook files", () => {
    const findings = findByRule(
      `const stripe = require("stripe");`,
      "VC005",
      "lib/payments.js",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC006: SQL Injection ─────────────────────────────────

describe("VC006 — SQL Injection", () => {
  it("flags template literals in queries", () => {
    const code = "const r = await db.query(`SELECT * FROM users WHERE id = ${userId}`);";
    const findings = findByRule(code, "VC006");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("flags string concatenation in queries", () => {
    const findings = findByRule(
      `db.query("SELECT * FROM users WHERE name = " + name);`,
      "VC006",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("passes with parameterized queries", () => {
    const findings = findByRule(
      `db.query("SELECT * FROM users WHERE id = ?", [userId]);`,
      "VC006",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC007: XSS ──────────────────────────────────────────

describe("VC007 — Cross-Site Scripting (XSS)", () => {
  it("flags dangerouslySetInnerHTML", () => {
    const findings = findByRule(
      `<div dangerouslySetInnerHTML={{ __html: userInput }} />`,
      "VC007",
      "Component.tsx",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
  });

  it("flags innerHTML assignment", () => {
    const findings = findByRule(
      `element.innerHTML = userContent;`,
      "VC007",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("flags document.write", () => {
    const findings = findByRule(
      `document.write(userData);`,
      "VC007",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("flags v-html in Vue", () => {
    const findings = findByRule(
      `<div v-html="userContent"></div>`,
      "VC007",
      "Component.vue",
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ─── VC008: No Rate Limiting ──────────────────────────────

describe("VC008 — No Rate Limiting", () => {
  it("flags server files without rate limiting", () => {
    const findings = findByRule(
      `const express = require("express");\nconst app = express();\napp.listen(3000);`,
      "VC008",
      "server.js",
    );
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("medium");
  });

  it("passes when rate limiting is present", () => {
    const findings = findByRule(
      `const rateLimit = require("express-rate-limit");\nconst app = express();\napp.use(rateLimit({ max: 100 }));\napp.listen(3000);`,
      "VC008",
      "server.js",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores non-server files", () => {
    const findings = findByRule(
      `const app = express();\napp.listen(3000);`,
      "VC008",
      "utils/helper.js",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC009: CORS Wildcard ─────────────────────────────────

describe("VC009 — CORS Wildcard", () => {
  it("flags cors() with no options", () => {
    const findings = findByRule(`app.use(cors());`, "VC009");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("medium");
  });

  it("flags origin: '*'", () => {
    const findings = findByRule(
      `app.use(cors({ origin: "*" }));`,
      "VC009",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("flags Access-Control-Allow-Origin: *", () => {
    const findings = findByRule(
      `res.setHeader("Access-Control-Allow-Origin", "*");`,
      "VC009",
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("passes with specific origin", () => {
    const findings = findByRule(
      `app.use(cors({ origin: "https://myapp.com" }));`,
      "VC009",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── VC010: Client-Side Only Auth ─────────────────────────

describe("VC010 — Client-Side Only Authorization", () => {
  it("flags admin checks without server verification", () => {
    const findings = findByRule(
      `export function Admin() {\n  const user = useUser();\n  {user?.role === "admin" && (\n    <div>Admin Panel</div>\n  )}\n}`,
      "VC010",
      "Admin.tsx",
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
  });

  it("passes when server-side check exists", () => {
    const findings = findByRule(
      `import { getServerSession } from "next-auth";\nexport function Admin() {\n  {isAdmin && <div>Admin Panel</div>}\n}`,
      "VC010",
      "Admin.tsx",
    );
    expect(findings.length).toBe(0);
  });

  it("ignores non-component files", () => {
    const findings = findByRule(
      `if (user.role === "admin") { doStuff(); }`,
      "VC010",
      "utils/permissions.js",
    );
    expect(findings.length).toBe(0);
  });
});

// ─── Integration: Full scan ───────────────────────────────

describe("Integration — Full Scan", () => {
  it("finds multiple issues in a vulnerable file", () => {
    const vulnerable = `
const express = require("express");
const cors = require("cors");
const app = express();
app.use(cors());
const API_KEY = "sk_test_FAKE_NOT_REAL_abcdefghijklmnopqrstuvwxyz";
app.get("/api/users", async (req, res) => {
  const result = await db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
  res.json(result);
});
app.post("/api/webhooks/stripe", async (req, res) => {
  const event = req.body;
  res.json({ ok: true });
});
app.listen(3000);
`;
    const findings = scan(vulnerable, "server.js");
    expect(findings.length).toBeGreaterThanOrEqual(4);

    const rules = new Set(findings.map((f) => f.rule));
    expect(rules.has("VC001")).toBe(true); // hardcoded key
    expect(rules.has("VC009")).toBe(true); // cors wildcard
  });

  it("returns zero findings for clean code", () => {
    const clean = `
import { getServerSession } from "next-auth";
import rateLimit from "express-rate-limit";
import cors from "cors";

const app = express();
app.use(cors({ origin: "https://myapp.com" }));
app.use(rateLimit({ max: 100 }));

app.get("/api/users", requireAuth, async (req, res) => {
  const users = await db.query("SELECT * FROM users WHERE org_id = ?", [req.orgId]);
  res.json(users);
});
app.listen(3000);
`;
    const findings = scan(clean, "server.js");
    expect(findings.length).toBe(0);
  });
});
