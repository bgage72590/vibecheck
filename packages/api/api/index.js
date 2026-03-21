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
      const isClientFile = filePath.match(/\.(jsx|tsx|vue|svelte)$/) || /["']use client["']/.test(content);
      const isEnvFile = filePath.match(/\.env/);
      if (!isClientFile && !isEnvFile) return [];
      const patterns = [];
      if (isClientFile) {
        patterns.push(/CLERK_SECRET_KEY/g, /AUTH0_CLIENT_SECRET/g, /NEXTAUTH_SECRET/g, /sk_(?:live|test)_[a-zA-Z0-9]{20,}/g);
      }
      if (isEnvFile) {
        patterns.push(/NEXT_PUBLIC_CLERK_SECRET/gi, /NEXT_PUBLIC_AUTH0_SECRET/gi, /NEXT_PUBLIC_NEXTAUTH_SECRET/gi);
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
  {
    id: "VC019", title: "Insecure Electron BrowserWindow Configuration", severity: "high", category: "Configuration",
    description: "Electron BrowserWindow with nodeIntegration enabled, contextIsolation disabled, or sandbox disabled allows renderer processes to access Node.js APIs, enabling remote code execution.",
    check(content, filePath) {
      if (!/BrowserWindow/i.test(content)) return [];
      const matches = [];
      const patterns = [/nodeIntegration\s*:\s*true/g, /contextIsolation\s*:\s*false/g, /sandbox\s*:\s*false/g, /webSecurity\s*:\s*false/g, /allowRunningInsecureContent\s*:\s*true/g];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, (m) =>
          `Fix: set ${m[0].split(":")[0].trim()} to the secure value. Enable contextIsolation, sandbox, webSecurity; disable nodeIntegration.`
        ));
      }
      if (/new\s+BrowserWindow\s*\(/g.test(content) && !/sandbox\s*:/i.test(content)) {
        matches.push(...findMatches(content, /new\s+BrowserWindow\s*\(/g, { ...this, title: "Electron BrowserWindow Missing sandbox:true" }, filePath, () =>
          "Add sandbox: true to BrowserWindow webPreferences."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC020", title: "Missing Content Security Policy (CSP)", severity: "high", category: "Configuration",
    description: "Without a Content-Security-Policy header or meta tag, your app is vulnerable to XSS and data injection attacks.",
    check(content, filePath) {
      if (filePath.match(/\.(html|htm)$/)) {
        if (!/Content-Security-Policy/i.test(content)) {
          return [{ rule: "VC020", title: this.title, severity: "high", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
            fix: 'Add a CSP meta tag: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'">' }];
        }
      }
      if (/BrowserWindow|electron/i.test(content) && /main|index/i.test(filePath)) {
        if (!/Content-Security-Policy/i.test(content) && !/helmet/i.test(content) && /(?:loadFile|loadURL)/i.test(content)) {
          return findMatches(content, /(?:loadFile|loadURL)\s*\(/g, this, filePath, () =>
            "Set CSP headers in Electron main process using session.defaultSession.webRequest.onHeadersReceived."
          );
        }
      }
      return [];
    },
  },
  {
    id: "VC021", title: "IPC/File Handler Without Path Validation", severity: "medium", category: "Injection",
    description: "IPC handlers that read/write files without path validation allow path traversal, exposing sensitive files.",
    check(content, filePath) {
      if (!/ipcMain\.handle|ipcMain\.on/i.test(content)) return [];
      if (!/readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream/i.test(content)) return [];
      if (/path\.resolve|path\.normalize|startsWith|\.includes\s*\(\s*["'`]\.\.["'`]\)|allowedPaths|safePath|validatePath|sanitizePath/i.test(content)) return [];
      return findMatches(content, /ipcMain\.(?:handle|on)\s*\(\s*["'`][^"'`]*(?:read|write|file|save|load|open|export)[^"'`]*["'`]/gi, this, filePath, () =>
        "Validate file paths in IPC handlers: ensure paths are within allowed directories, reject '..' sequences, block sensitive dirs (.ssh, .env)."
      );
    },
  },
  {
    id: "VC022", title: "HTML Export/Render Without Sanitization", severity: "critical", category: "Injection",
    description: "Generating HTML from user content without sanitization allows stored XSS attacks.",
    check(content, filePath) {
      if (/DOMPurify|sanitize|escapeHtml|escape|xss|encode|htmlEncode/i.test(content)) return [];
      const patterns = [
        /`<[^`]*\$\{[^}]*(?:content|title|body|text|name|message|description|input|value|data)[^}]*\}[^`]*>`/gi,
        /["']<[^"']*['"]\s*\+\s*(?:content|title|body|text|message|data|doc\.|post\.|article\.)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Sanitize user content before embedding in HTML. Use DOMPurify.sanitize(content) or escape HTML entities."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC023", title: "Prototype Pollution Risk", severity: "high", category: "Injection",
    description: "Parsing JSON from localStorage/external sources and merging without validation enables prototype pollution.",
    check(content, filePath) {
      if (/schema|validate|sanitize|whitelist|allowedKeys|Object\.freeze|zod|yup|joi|ajv/i.test(content)) return [];
      const matches = [];
      if (/Object\.assign\s*\([^)]*JSON\.parse|\.\.\.JSON\.parse/i.test(content)) {
        matches.push(...findMatches(content, /Object\.assign\s*\([^)]*JSON\.parse|\.\.\.JSON\.parse/g, this, filePath, () =>
          "Validate parsed data against an expected schema. Check for __proto__ and constructor keys."
        ));
      }
      const storagePatterns = [/JSON\.parse\s*\(\s*(?:localStorage|sessionStorage)\.getItem/g];
      for (const p of storagePatterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Validate localStorage data against an expected schema before using it."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC024", title: "File Write/Save Without Size Limit", severity: "medium", category: "Availability",
    description: "File save/upload handlers without size validation can lead to denial-of-service.",
    check(content, filePath) {
      if (!/writeFile|writeFileSync/i.test(content)) return [];
      if (/size|length|byteLength|maxSize|MAX_SIZE|sizeLimit|content-length/i.test(content)) return [];
      return findMatches(content, /(?:writeFile|writeFileSync)\s*\(/g, this, filePath, () =>
        "Add file size validation before writing. Check content.length against a maximum (e.g., 10MB)."
      );
    },
  },
  {
    id: "VC025", title: "Unsanitized Filename in File Operations", severity: "medium", category: "Injection",
    description: "User-supplied filenames without sanitization can enable path traversal or command injection.",
    check(content, filePath) {
      if (/sanitize|cleanFilename|safeFilename|replace\s*\(\s*\/\[.*\]\//i.test(content)) return [];
      const patterns = [
        /(?:writeFile|writeFileSync|createWriteStream|rename|copyFile)\s*\(\s*(?:`[^`]*\$\{|[^"'`\s,]+\s*\+)/g,
        /\.download\s*=\s*(?!["'`])/g,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Sanitize filenames: strip path separators, special chars, and '..' sequences. Example: name.replace(/[^a-zA-Z0-9._-]/g, '_')"
        ));
      }
      return matches;
    },
  },
  {
    id: "VC026", title: "Electron: External Navigation Not Blocked", severity: "medium", category: "Configuration",
    description: "Electron apps that don't block external URL navigation are vulnerable to phishing.",
    check(content, filePath) {
      if (!/BrowserWindow|electron/i.test(content) || !/main|index/i.test(filePath)) return [];
      if (/will-navigate|new-window|setWindowOpenHandler/i.test(content)) return [];
      if (/new\s+BrowserWindow/i.test(content)) {
        return findMatches(content, /new\s+BrowserWindow\s*\(/g, this, filePath, () =>
          "Block external navigation: win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file://')) e.preventDefault(); });"
        );
      }
      return [];
    },
  },
  {
    id: "VC027", title: "Missing Security Meta Tags / Headers", severity: "medium", category: "Configuration",
    description: "HTML pages without X-Content-Type-Options or referrer policy are susceptible to MIME-sniffing and info leakage.",
    check(content, filePath) {
      if (!filePath.match(/\.(html|htm)$/)) return [];
      const matches = [];
      if (!/X-Content-Type-Options/i.test(content) && !/<meta[^>]*nosniff/i.test(content)) {
        matches.push({ rule: "VC027", title: "Missing X-Content-Type-Options", severity: "medium", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: 'Add <meta http-equiv="X-Content-Type-Options" content="nosniff">' });
      }
      if (!/referrer/i.test(content)) {
        matches.push({ rule: "VC027", title: "Missing Referrer Policy", severity: "medium", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: 'Add <meta name="referrer" content="no-referrer">' });
      }
      return matches;
    },
  },
  {
    id: "VC028", title: "Unvalidated API Request Parameters", severity: "high", category: "Injection",
    description: "API requests with unvalidated user input (API keys, model names) can be exploited for injection or unauthorized access.",
    check(content, filePath) {
      if (/validate|sanitize|regex|test\(|match\(|allowList|whitelist|enum|includes\(/i.test(content)) return [];
      const matches = [];
      if (/model\s*[:=]\s*(?:req\.body|params|input|body)\./i.test(content) && /(?:openai|anthropic|claude|gpt|llm)/i.test(content)) {
        if (!/allowedModels|validModels|models\s*\.\s*includes|model.*===|model.*includes/i.test(content)) {
          matches.push(...findMatches(content, /model\s*[:=]\s*(?:req\.body|params|input|body)\./gi, this, filePath, () =>
            "Validate model selection against an allowlist of approved models."
          ));
        }
      }
      const apiKeyPatterns = [/(?:apiKey|api_key|authorization)\s*[:=]\s*(?:req\.body|req\.query|params|input|formData|body)\./gi];
      for (const p of apiKeyPatterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Validate API key format before use (check prefix and length)."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC029", title: "Unvalidated Event or PostMessage Data", severity: "medium", category: "Injection",
    description: "Message event handlers without origin checking or custom events without type-checking are vulnerable to injection.",
    check(content, filePath) {
      const matches = [];
      if (/addEventListener\s*\(\s*["'`]message["'`]/i.test(content)) {
        if (!/event\.origin|e\.origin|message\.origin/i.test(content)) {
          matches.push(...findMatches(content, /addEventListener\s*\(\s*["'`]message["'`]/g, this, filePath, () =>
            "Verify event.origin in message handlers. Example: if (event.origin !== 'https://trusted.com') return;"
          ));
        }
      }
      if (/new\s+CustomEvent\s*\(/i.test(content) && !/typeof\s|instanceof|z\.|schema|validate/i.test(content)) {
        matches.push(...findMatches(content, /new\s+CustomEvent\s*\(/g, this, filePath, () =>
          "Type-check custom event data before using it."
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
