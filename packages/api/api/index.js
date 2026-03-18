const { Hono } = require("hono");
const { handle } = require("hono/vercel");

const app = new Hono().basePath("/api");

// ────────────────────────────────────────────
// INLINE SCANNER ENGINE (from custom-rules.ts)
// ────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".go", ".rs", ".java", ".php",
  ".vue", ".svelte", ".astro",
  ".env", ".yaml", ".yml", ".toml", ".json",
  ".html", ".htm", ".sql",
]);

function getSnippet(content, lineNum, context = 2) {
  const lines = content.split("\n");
  const start = Math.max(0, lineNum - 1 - context);
  const end = Math.min(lines.length, lineNum + context);
  return lines
    .slice(start, end)
    .map((line, i) => {
      const num = start + i + 1;
      const marker = num === lineNum ? ">" : " ";
      return `${marker} ${String(num).padStart(5)} | ${line}`;
    })
    .join("\n");
}

function findMatches(content, pattern, rule, filePath, fixFn) {
  const matches = [];
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let m;
  while ((m = re.exec(content)) !== null) {
    const lineNum = content.substring(0, m.index).split("\n").length;
    matches.push({
      rule: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: rule.category,
      file: filePath,
      line: lineNum,
      snippet: getSnippet(content, lineNum),
      fix: fixFn ? fixFn(m) : undefined,
    });
  }
  return matches;
}

const rules = [
  {
    id: "VC001", title: "Hardcoded API Key or Secret", severity: "critical", category: "Secrets",
    description: "API keys, tokens, or secrets hardcoded in source code can be extracted by anyone with access to the code.",
    check(content, filePath) {
      if (filePath.endsWith(".example") || filePath.endsWith(".template")) return [];
      const patterns = [
        /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]/gi,
        /(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/g,
        /(?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]{20,}/g,
        /(?:supabase[_-]?(?:anon|service)[_-]?key|SUPABASE_(?:ANON|SERVICE_ROLE)_KEY)\s*[:=]\s*["'`](eyJ[a-zA-Z0-9_-]{50,})["'`]/gi,
        /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,
        /(?:token|secret|password|passwd|pwd)\s*[:=]\s*["'`]([a-zA-Z0-9_\-!@#$%^&*]{12,})["'`]/gi,
        /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
        /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:]+:[^@]+@[^/\s"'`]+/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move this secret to an environment variable and add it to .env (not committed to git)."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC002", title: "Environment File May Be Committed", severity: "high", category: "Secrets",
    description: ".env files containing secrets may be committed to version control.",
    check(content, filePath) {
      if (!filePath.match(/\.env(?:\.[a-z]+)?$/) || filePath.includes("example")) return [];
      if (!/(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE_URL)\s*=/i.test(content)) return [];
      return [{ rule: "VC002", title: this.title, severity: "high", category: "Secrets", file: filePath, line: 1, snippet: getSnippet(content, 1), fix: 'Add ".env*" to your .gitignore and remove from git.' }];
    },
  },
  {
    id: "VC003", title: "API Route Missing Authentication", severity: "high", category: "Authentication",
    description: "API routes without authentication checks allow unauthorized access.",
    check(content, filePath) {
      if (!/(?:\/api\/|routes?\/|controllers?\/|endpoints?\/)/.test(filePath) && !filePath.includes("server.")) return [];
      const authPatterns = [/auth/i, /session/i, /jwt/i, /bearer/i, /middleware/i, /getUser/i, /currentUser/i, /requireAuth/i, /clerk/i, /supabase\.auth/i];
      if (authPatterns.some(p => p.test(content))) return [];
      const routePatterns = [
        /\.(get|post|put|patch|delete)\s*\(\s*["'`][^"'`]+["'`]\s*,\s*(?:async\s+)?\(?(?:req|c|ctx)/gi,
        /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/gi,
      ];
      const matches = [];
      for (const p of routePatterns) {
        matches.push(...findMatches(content, p, this, filePath, () => "Add authentication middleware to protect this route."));
      }
      return matches;
    },
  },
  {
    id: "VC004", title: "Supabase Client Without Row Level Security", severity: "critical", category: "Authorization",
    description: "Using Supabase with the service role key or bypassing RLS exposes all database rows.",
    check(content, filePath) {
      const matches = [];
      if (/service_role/i.test(content) && (/["']use client["']/.test(content) || filePath.match(/\.(jsx|tsx|vue|svelte)$/))) {
        matches.push(...findMatches(content, /service_role/gi, this, filePath, () => "Never expose the service_role key in client-side code."));
      }
      if (/createClient/i.test(content) && /\.from\(/.test(content) && /\.rpc\(|auth\.admin/i.test(content)) {
        matches.push(...findMatches(content, /\.rpc\(|auth\.admin/gi, { ...this, title: "Supabase RLS Bypass Detected" }, filePath, () => "Ensure RLS policies are enabled on all tables."));
      }
      return matches;
    },
  },
  {
    id: "VC005", title: "Unprotected Stripe Webhook Endpoint", severity: "critical", category: "Payment Security",
    description: "Stripe webhook endpoints without signature verification allow attackers to fake payment events.",
    check(content, filePath) {
      if (!/stripe|webhook/i.test(content)) return [];
      if (!/webhook/i.test(filePath) && !/(?:post|handler).*webhook/i.test(content)) return [];
      if (/constructEvent|verifyHeader|stripe-signature|webhook_secret/i.test(content)) return [];
      return findMatches(content, /webhook/gi, this, filePath, () => "Verify the Stripe webhook signature using stripe.webhooks.constructEvent().");
    },
  },
  {
    id: "VC006", title: "Potential SQL Injection", severity: "critical", category: "Injection",
    description: "String concatenation in SQL queries allows attackers to execute arbitrary database commands.",
    check(content, filePath) {
      if (/\?\s*,|\$\d+|:[\w]+|\bprepare\b|\bplaceholder\b/i.test(content)) return [];
      const patterns = [
        /(?:query|execute|raw|sql)\s*\(\s*`[^`]*\$\{/gi,
        /(?:query|execute)\s*\(\s*["'][^"']*["']\s*\+/gi,
        /(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\s+.*\$\{/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () => "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])"));
      }
      return matches;
    },
  },
  {
    id: "VC007", title: "Potential Cross-Site Scripting (XSS)", severity: "high", category: "Injection",
    description: "Rendering user input without sanitization allows attackers to inject malicious scripts.",
    check(content, filePath) {
      const patterns = [/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g, /\.innerHTML\s*=\s*(?!["'`]\s*$)/gm, /document\.write\s*\(/g, /v-html\s*=/g, /\{@html\s/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () => "Sanitize user input: DOMPurify.sanitize(userInput)"));
      }
      return matches;
    },
  },
  {
    id: "VC008", title: "API Endpoint Without Rate Limiting", severity: "medium", category: "Availability",
    description: "API endpoints without rate limiting are vulnerable to abuse.",
    check(content, filePath) {
      if (!/(?:server|app|index|main)\.[jt]sx?$/.test(filePath)) return [];
      if (!/(?:express|hono|fastify|koa|next|createServer|listen\()/i.test(content)) return [];
      if (/rate.?limit|throttle/i.test(content)) return [];
      return [{ rule: "VC008", title: this.title, severity: "medium", category: "Availability", file: filePath, line: 1, snippet: getSnippet(content, 1), fix: "Add rate limiting middleware to your server." }];
    },
  },
  {
    id: "VC009", title: "CORS Allows All Origins", severity: "medium", category: "Configuration",
    description: "Wildcard CORS allows any website to make requests to your API.",
    check(content, filePath) {
      const patterns = [/cors\(\s*\)/g, /origin\s*:\s*["'`]\*["'`]/g, /["'`]Access-Control-Allow-Origin["'`]\s*,\s*["'`]\*["'`]/g, /origin\s*:\s*true/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () => "Restrict CORS: cors({ origin: 'https://yourdomain.com' })"));
      }
      return matches;
    },
  },
  {
    id: "VC010", title: "Client-Side Only Authorization", severity: "high", category: "Authorization",
    description: "Hiding UI elements without server-side checks lets attackers bypass restrictions.",
    check(content, filePath) {
      if (!filePath.match(/\.(jsx|tsx|vue|svelte)$/)) return [];
      if (/getServerSession|getUser|server|api\/auth|middleware/i.test(content)) return [];
      const matches = [];
      const patterns = [/\{.*(?:isAdmin|role\s*===?\s*["'`]admin["'`]|user\.role).*&&/gi];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () => "Always verify permissions on the server/API side too."));
      }
      return matches;
    },
  },
];

function runScan(files) {
  const findings = [];
  for (const { path, content } of files) {
    for (const rule of rules) {
      const matches = rule.check(content, path);
      for (const match of matches) {
        findings.push({
          id: `${match.rule}-${match.file}:${match.line}`,
          rule: match.rule,
          severity: match.severity,
          title: match.title,
          description: rule.description,
          file: match.file,
          line: match.line,
          snippet: match.snippet,
          fix: match.fix,
          category: match.category,
          source: "custom",
        });
      }
    }
  }
  return findings;
}

// ────────────────────────────────────────────
// CORS middleware
// ────────────────────────────────────────────

app.use("*", async (c, next) => {
  const origin = c.req.header("Origin") || "*";
  c.header("Access-Control-Allow-Origin", origin);
  c.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  c.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
  c.header("Access-Control-Max-Age", "86400");
  if (c.req.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }
  await next();
});

// ────────────────────────────────────────────
// UPLOAD + SCAN ENDPOINT
// ────────────────────────────────────────────

// Rate limiting for uploads (in-memory, per-instance)
const uploadRateStore = new Map();

app.post("/scans/upload", async (c) => {
  // Rate limit: 5 per minute per IP
  const ip = c.req.header("x-forwarded-for") || c.req.header("x-real-ip") || "unknown";
  const now = Date.now();
  const rateEntry = uploadRateStore.get(ip);
  if (rateEntry && now < rateEntry.resetAt) {
    if (rateEntry.count >= 5) {
      return c.json({ error: "Too many uploads. Try again in a minute." }, 429);
    }
    rateEntry.count++;
  } else {
    uploadRateStore.set(ip, { count: 1, resetAt: now + 60000 });
  }

  try {
    const contentType = c.req.header("content-type") || "";

    if (!contentType.includes("multipart/form-data")) {
      return c.json({ error: "Expected multipart/form-data" }, 400);
    }

    const body = await c.req.parseBody({ all: true });
    const startTime = Date.now();
    const filesToScan = [];

    // Handle ZIP upload
    if (body.zip) {
      const zipFile = body.zip;
      if (!(zipFile instanceof File)) {
        return c.json({ error: "Invalid zip file" }, 400);
      }

      // Size check (5MB)
      if (zipFile.size > 5 * 1024 * 1024) {
        return c.json({ error: "File too large. Maximum 5MB." }, 413);
      }

      const { unzipSync } = require("fflate");
      const buffer = new Uint8Array(await zipFile.arrayBuffer());
      let entries;
      try {
        entries = unzipSync(buffer);
      } catch {
        return c.json({ error: "Invalid or corrupted ZIP file." }, 400);
      }

      // ZIP bomb protection: 50MB uncompressed max
      let totalSize = 0;
      const MAX_UNCOMPRESSED = 50 * 1024 * 1024;

      for (const [path, data] of Object.entries(entries)) {
        totalSize += data.length;
        if (totalSize > MAX_UNCOMPRESSED) {
          return c.json({ error: "ZIP file too large when extracted. Maximum 50MB uncompressed." }, 413);
        }

        // Path traversal protection
        if (path.includes("..") || path.startsWith("/")) continue;
        // Skip directories
        if (path.endsWith("/")) continue;
        // Skip nested ZIPs
        if (path.endsWith(".zip")) continue;

        // Extension filter
        const ext = "." + path.split(".").pop().toLowerCase();
        if (!SOURCE_EXTENSIONS.has(ext)) continue;

        // Decode to string (skip binary)
        try {
          const content = new TextDecoder("utf-8", { fatal: true }).decode(data);
          filesToScan.push({ path, content });
        } catch {
          // Skip binary files
        }
      }
    }
    // Handle individual file uploads
    else {
      const files = body.files;
      if (!files) {
        return c.json({ error: "No files provided. Upload files or a ZIP." }, 400);
      }

      const fileList = Array.isArray(files) ? files : [files];

      // Size check
      let totalSize = 0;
      for (const file of fileList) {
        if (!(file instanceof File)) continue;
        totalSize += file.size;
        if (totalSize > 5 * 1024 * 1024) {
          return c.json({ error: "Total file size exceeds 5MB limit." }, 413);
        }
      }

      // File count cap
      if (fileList.length > 200) {
        return c.json({ error: "Too many files. Maximum 200 files per upload." }, 400);
      }

      for (const file of fileList) {
        if (!(file instanceof File)) continue;

        const fileName = file.name || "unknown";
        const ext = "." + fileName.split(".").pop().toLowerCase();
        if (!SOURCE_EXTENSIONS.has(ext)) continue;

        // Path traversal protection
        if (fileName.includes("..") || fileName.startsWith("/")) continue;

        try {
          const content = await file.text();
          filesToScan.push({ path: fileName, content });
        } catch {
          // Skip unreadable files
        }
      }
    }

    if (filesToScan.length === 0) {
      return c.json({ error: "No scannable source files found. Upload .js, .ts, .py, .env, or other source files." }, 400);
    }

    // Run the scanner
    const findings = runScan(filesToScan);
    const duration = Date.now() - startTime;

    return c.json({
      findings,
      filesScanned: filesToScan.length,
      duration,
      criticalCount: findings.filter(f => f.severity === "critical").length,
      highCount: findings.filter(f => f.severity === "high").length,
      mediumCount: findings.filter(f => f.severity === "medium").length,
      lowCount: findings.filter(f => f.severity === "low").length,
    });
  } catch (err) {
    console.error("Upload scan error:", err);
    return c.json({ error: "Scan failed. Please try again." }, 500);
  }
});

// ────────────────────────────────────────────
// EXISTING ROUTES
// ────────────────────────────────────────────

app.get("/", (c) => {
  return c.json({
    name: "vibecheck-api",
    version: "0.1.0",
    status: "ok",
  });
});

app.get("/usage/check", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ allowed: true, plan: "free", remaining: 3, limit: 3 });
});

app.post("/scans", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ ok: true }, 201);
});

app.get("/scans", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }
  return c.json({ scans: [] });
});

app.post("/users/sync", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
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

app.all("/*", (c) => {
  return c.json({ name: "vibecheck-api", version: "0.1.0", status: "ok" });
});

module.exports = handle(app);
