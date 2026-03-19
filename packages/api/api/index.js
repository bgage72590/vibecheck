const { Hono } = require("hono");
const { handle } = require("hono/vercel");

const app = new Hono().basePath("/api");

// ────────────────────────────────────────────
// INLINE SCANNER ENGINE (from custom-rules.ts)
// ────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".vue", ".svelte", ".astro",
  ".py", ".rb", ".go", ".rs", ".java", ".php",
  ".swift", ".kt", ".kts", ".dart", ".cs",
  ".c", ".cpp", ".h",
  ".sh", ".bash", ".zsh",
  ".env", ".yaml", ".yml", ".toml", ".json", ".xml",
  ".html", ".htm", ".sql",
  ".properties", ".ini", ".cfg", ".conf",
  ".tf", ".hcl", ".dockerfile",
  ".erb", ".jinja", ".j2",
  ".gradle",
  ".r", ".lua", ".pl", ".pm", ".ex", ".exs",
  ".ipynb", ".md",
  ".prisma", ".plist", ".pbxproj", ".entitlements", ".rules", ".csv",
]);

const SOURCE_FILENAMES = new Set([
  "Dockerfile", "Makefile", "Gemfile", "Rakefile",
  ".env.local", ".env.production", ".env.development", ".env.example",
  "package.json", "Cargo.toml", "go.mod", "requirements.txt", "Pipfile",
  "next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
  "firebase.json", ".firebaserc", "firestore.rules",
  "app.json", "app.config.js", "eas.json",
  "wrangler.toml", "netlify.toml",
  "drizzle.config.ts", "drizzle.config.js",
  "Procfile", "Caddyfile", "nginx.conf",
  "AndroidManifest.xml",
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
  {
    id: "VC011", title: "Secret in NEXT_PUBLIC_ Environment Variable", severity: "critical", category: "Secrets",
    description: "NEXT_PUBLIC_ variables are exposed to the browser. Secrets placed here are visible to anyone.",
    check(content, filePath) {
      if (!filePath.match(/\.env/) && !filePath.match(/next\.config/)) return [];
      const patterns = [
        /NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=\s*.+/gi,
        /NEXT_PUBLIC_[A-Z_]*(?:SUPABASE_SERVICE|CLERK_SECRET|STRIPE_SECRET)[A-Z_]*\s*=\s*.+/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Remove the NEXT_PUBLIC_ prefix. Only use NEXT_PUBLIC_ for values safe to expose in the browser."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC012", title: "Firebase Config with API Key in Client Code", severity: "medium", category: "Configuration",
    description: "Firebase config objects in client code expose your API key. While Firebase API keys aren't secret, they should be restricted in the Firebase console.",
    check(content, filePath) {
      if (!/firebase/i.test(content)) return [];
      const patterns = [
        /firebaseConfig\s*=\s*\{[^}]*apiKey\s*:/gi,
        /initializeApp\s*\(\s*\{[^}]*apiKey\s*:/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move Firebase config to environment variables. Restrict the API key in Firebase Console > Project Settings > API restrictions."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC013", title: "Supabase Anon Key Used for Admin Operations", severity: "high", category: "Authorization",
    description: "Using the Supabase anon key for operations that require elevated privileges is insecure.",
    check(content, filePath) {
      if (!/supabase/i.test(content)) return [];
      if (!/anon/i.test(content)) return [];
      const patterns = [
        /supabase[^.]*\.auth\.admin/gi,
        /supabase[^.]*\.rpc\s*\(/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        if (/service_role/i.test(content)) continue;
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Use the service_role key on the server side for admin operations. Never expose it to the client."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC014", title: ".env File Not in .gitignore", severity: "high", category: "Secrets",
    description: "If .env is not listed in .gitignore, secrets will be committed to version control.",
    check(content, filePath) {
      if (!filePath.endsWith(".gitignore")) return [];
      if (/\.env/i.test(content)) return [];
      return [{
        rule: "VC014", title: this.title, severity: "high", category: "Secrets",
        file: filePath, line: 1, snippet: getSnippet(content, 1),
        fix: 'Add ".env*" to your .gitignore file to prevent committing secrets.',
      }];
    },
  },
  {
    id: "VC015", title: "Use of eval() or Function Constructor", severity: "high", category: "Injection",
    description: "eval() and new Function() execute arbitrary code, creating severe injection risks. Common in AI-generated code.",
    check(content, filePath) {
      if (filePath.includes("node_modules") || filePath.includes(".min.")) return [];
      const patterns = [
        /\beval\s*\(/g,
        /new\s+Function\s*\(/g,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Replace eval() with JSON.parse() for data, or a proper parser for expressions. Never pass user input to eval()."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC016", title: "Unvalidated Redirect", severity: "high", category: "Injection",
    description: "Redirecting users to URLs from untrusted input enables phishing attacks.",
    check(content, filePath) {
      const patterns = [
        /window\.location\s*=\s*(?!["'`]https?:\/\/)/g,
        /window\.location\.href\s*=\s*(?!["'`]https?:\/\/)/g,
        /window\.location\.assign\s*\(\s*(?!["'`]https?:\/\/)/g,
        /window\.location\.replace\s*\(\s*(?!["'`]https?:\/\/)/g,
        /res\.redirect\s*\(\s*(?:req\.|params\.|query\.)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Validate redirect URLs against an allowlist of trusted domains. Never redirect to user-supplied URLs directly."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC017", title: "Insecure Cookie Settings", severity: "medium", category: "Configuration",
    description: "Cookies without httpOnly, secure, or sameSite flags are vulnerable to theft and CSRF attacks.",
    check(content, filePath) {
      if (!/cookie/i.test(content)) return [];
      // Look for cookie-setting code without security flags
      const setCookiePattern = /(?:set-cookie|setCookie|cookie\s*=|res\.cookie\s*\()/gi;
      if (!setCookiePattern.test(content)) return [];
      const hasHttpOnly = /httpOnly\s*:\s*true|httponly/i.test(content);
      const hasSecure = /secure\s*:\s*true|;\s*secure/i.test(content);
      const hasSameSite = /sameSite\s*:|samesite/i.test(content);
      const matches = [];
      if (!hasHttpOnly || !hasSecure || !hasSameSite) {
        const missing = [];
        if (!hasHttpOnly) missing.push("httpOnly");
        if (!hasSecure) missing.push("secure");
        if (!hasSameSite) missing.push("sameSite");
        matches.push(...findMatches(content, /(?:set-cookie|setCookie|cookie\s*=|res\.cookie\s*\()/gi, this, filePath, () =>
          `Add missing cookie flags: ${missing.join(", ")}. Example: { httpOnly: true, secure: true, sameSite: 'lax' }`
        ));
      }
      return matches;
    },
  },
  {
    id: "VC018", title: "Exposed Clerk/Auth Secret Key", severity: "critical", category: "Secrets",
    description: "Auth provider secret keys (Clerk, Auth0, NextAuth) must never be in client-side code or NEXT_PUBLIC_ variables.",
    check(content, filePath) {
      // Only check client-side files
      const isClientFile = filePath.match(/\.(jsx|tsx|vue|svelte)$/) || /["']use client["']/.test(content);
      const isEnvFile = filePath.match(/\.env/);
      if (!isClientFile && !isEnvFile) return [];
      const patterns = [];
      if (isClientFile) {
        patterns.push(
          /CLERK_SECRET_KEY/g,
          /AUTH0_CLIENT_SECRET/g,
          /NEXTAUTH_SECRET/g,
          /sk_(?:live|test)_[a-zA-Z0-9]{20,}/g,
        );
      }
      if (isEnvFile) {
        patterns.push(
          /NEXT_PUBLIC_CLERK_SECRET/gi,
          /NEXT_PUBLIC_AUTH0_SECRET/gi,
          /NEXT_PUBLIC_NEXTAUTH_SECRET/gi,
        );
      }
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move this secret to a server-side environment variable (without the NEXT_PUBLIC_ prefix). Never expose auth secrets to the browser."
        ));
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

      // Size check (25MB for ZIP uploads)
      if (zipFile.size > 25 * 1024 * 1024) {
        return c.json({ error: "ZIP too large. Maximum 25MB." }, 413);
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

        // Extension or filename filter
        const ext = "." + path.split(".").pop().toLowerCase();
        const baseName = path.split("/").pop() || "";
        if (!SOURCE_EXTENSIONS.has(ext) && !SOURCE_FILENAMES.has(baseName)) continue;

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
        if (!SOURCE_EXTENSIONS.has(ext) && !SOURCE_FILENAMES.has(fileName)) continue;

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
// JSON UPLOAD + SCAN (client extracts ZIP, sends source text only)
// ────────────────────────────────────────────

app.post("/scans/upload-json", async (c) => {
  // Rate limit: 10 per minute per IP
  const ip = c.req.header("x-forwarded-for") || c.req.header("x-real-ip") || "unknown";
  const now = Date.now();
  const rateEntry = uploadRateStore.get(ip);
  if (rateEntry && now < rateEntry.resetAt) {
    if (rateEntry.count >= 10) {
      return c.json({ error: "Too many scans. Try again in a minute." }, 429);
    }
    rateEntry.count++;
  } else {
    uploadRateStore.set(ip, { count: 1, resetAt: now + 60000 });
  }

  try {
    const body = await c.req.json();

    if (!body.files || !Array.isArray(body.files)) {
      return c.json({ error: "Expected { files: [{ path, content }] }" }, 400);
    }

    if (body.files.length === 0) {
      return c.json({ error: "No files provided." }, 400);
    }

    if (body.files.length > 500) {
      return c.json({ error: "Too many files. Maximum 500." }, 400);
    }

    const startTime = Date.now();
    const filesToScan = [];

    for (const file of body.files) {
      if (!file.path || typeof file.content !== "string") continue;
      // Path traversal protection
      if (file.path.includes("..") || file.path.startsWith("/")) continue;
      // Size cap per file (500KB)
      if (file.content.length > 500 * 1024) continue;
      filesToScan.push({ path: file.path, content: file.content });
    }

    if (filesToScan.length === 0) {
      return c.json({ error: "No valid source files to scan." }, 400);
    }

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
    console.error("JSON scan error:", err);
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
