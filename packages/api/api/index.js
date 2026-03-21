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
  {
    id: "VC030", title: "Insecure Deserialization", severity: "critical", category: "Injection",
    description: "Deserializing untrusted data (pickle, unserialize, yaml.load) can execute arbitrary code.",
    check(content, filePath) {
      const patterns = [/pickle\.loads?\s*\(/g, /cPickle\.loads?\s*\(/g, /unserialize\s*\(/g, /Marshal\.load\s*\(/g, /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g, /yaml\.unsafe_load\s*\(/g, /ObjectInputStream\s*\(/g, /serialize\.unserialize\s*\(/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Never deserialize untrusted data. Use JSON instead of pickle/Marshal/unserialize. For YAML, use yaml.safe_load()."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC031", title: "Hardcoded JWT Secret", severity: "critical", category: "Secrets",
    description: "JWT tokens signed with a hardcoded string secret can be forged by anyone who reads the source code.",
    check(content, filePath) {
      if (filePath.endsWith(".example") || filePath.endsWith(".template") || filePath.includes("test")) return [];
      const patterns = [/jwt\.sign\s*\([^,]+,\s*["'`][^"'`]{3,}["'`]/g, /jwt\.verify\s*\([^,]+,\s*["'`][^"'`]{3,}["'`]/g, /JWT_SECRET\s*[:=]\s*["'`][^"'`]{3,}["'`]/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move JWT secret to an environment variable: jwt.sign(payload, process.env.JWT_SECRET). Use a strong, random secret (256+ bits)."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC032", title: "Missing HTTPS Enforcement", severity: "high", category: "Configuration",
    description: "HTTP URLs in production code expose data to man-in-the-middle attacks.",
    check(content, filePath) {
      if (filePath.endsWith(".example") || filePath.includes("test") || filePath.match(/\.(md|txt)$/)) return [];
      const httpPattern = /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)[^"'`\s]+["'`]/g;
      return findMatches(content, httpPattern, this, filePath, () =>
        "Use https:// instead of http:// for all production URLs. Add HSTS header."
      );
    },
  },
  {
    id: "VC033", title: "Debug/Development Mode Exposed", severity: "high", category: "Configuration",
    description: "Debug mode or development config left in production exposes internal details.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.endsWith(".example") || filePath.match(/\.env\.development$/)) return [];
      const patterns = [/DEBUG\s*[:=]\s*(?:true|1|["'`]true["'`]|["'`]\*["'`])/g, /DEBUG\s*=\s*True/g, /app\.debug\s*=\s*True/g, /app\.run\s*\([^)]*debug\s*=\s*True/g, /devtool\s*:\s*["'`](?:eval|cheap|source-map|inline-source-map)["'`]/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Disable debug mode in production. Use environment variables: DEBUG = process.env.NODE_ENV !== 'production'."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC034", title: "Insecure Randomness for Security-Sensitive Values", severity: "high", category: "Cryptography",
    description: "Math.random() is not cryptographically secure. Using it for tokens, IDs, or passwords makes them predictable.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock") || filePath.includes("seed")) return [];
      const matches = [];
      matches.push(...findMatches(content, /(?:token|secret|session|password|otp|nonce|salt|key|csrf|auth|verify|code)\s*[:=].*Math\.random/gi, this, filePath, () =>
        "Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive values."
      ));
      matches.push(...findMatches(content, /(?:id|uuid|guid|identifier)\s*[:=].*Math\.random/gi, this, filePath, () =>
        "Use crypto.randomUUID() for generating unique IDs."
      ));
      return matches;
    },
  },
  {
    id: "VC035", title: "Open Redirect via URL Parameters", severity: "high", category: "Injection",
    description: "Redirect parameters like ?redirect_url= passed directly to redirects enable phishing.",
    check(content, filePath) {
      if (/allowedUrls|allowedDomains|allowedHosts|safeDomain|whitelist|startsWith.*https|new URL.*hostname/i.test(content)) return [];
      const patterns = [
        /(?:redirect_url|redirect_uri|return_to|return_url|next|callback_url|continue|goto|target|dest|destination)\s*(?:=|:)\s*(?:req\.query|req\.params|searchParams|query|params)\./gi,
        /redirect\s*\(\s*(?:req\.query|req\.params|searchParams\.get)\s*\(\s*["'`](?:redirect|return|next|callback|url|goto)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Validate redirect URLs against an allowlist of trusted domains."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC036", title: "React App Missing Error Boundary", severity: "medium", category: "Configuration",
    description: "React apps without error boundaries display raw stack traces to users when crashes occur.",
    check(content, filePath) {
      if (!filePath.match(/(?:layout|_app|App|main)\.[jt]sx?$/)) return [];
      if (!/(?:React|react|jsx|tsx)/i.test(content)) return [];
      if (/ErrorBoundary|componentDidCatch|getDerivedStateFromError|error-boundary/i.test(content)) return [];
      if (/children|<[A-Z]|Component|Outlet/i.test(content)) {
        return [{ rule: "VC036", title: this.title, severity: "medium", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: "Wrap your app in an ErrorBoundary component." }];
      }
      return [];
    },
  },
  {
    id: "VC037", title: "Stack Traces Exposed in API Responses", severity: "medium", category: "Information Leakage",
    description: "Returning error.stack in API responses reveals internal code paths to attackers.",
    check(content, filePath) {
      if (!/(?:\/api\/|routes?\/|controllers?\/|server\.|middleware)/i.test(filePath)) return [];
      if (/process\.env\.NODE_ENV\s*(?:===|!==)\s*["'`]production["'`]/i.test(content)) return [];
      const patterns = [
        /(?:res\.(?:json|send|status)|c\.json|return.*json)\s*\([^)]*(?:err\.stack|error\.stack|e\.stack)/gi,
        /(?:message|error)\s*:\s*(?:err|error|e)\.(?:stack|message)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Never expose error.stack to clients. Return generic messages: { error: 'Something went wrong' }."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC038", title: "Insecure File Upload Validation", severity: "high", category: "Injection",
    description: "File uploads validated only by extension (not MIME type) allow uploading executable files.",
    check(content, filePath) {
      if (!/upload|multer|formidable|busboy|multipart/i.test(content)) return [];
      const hasExtCheck = /\.(?:endsWith|match|test)\s*\([^)]*(?:\.jpg|\.png|\.pdf|\.doc|ext)/i.test(content);
      const hasMimeCheck = /mimetype|content-type|file\.type|mime|magic\.detect|file-type/i.test(content);
      if (hasExtCheck && !hasMimeCheck) {
        return findMatches(content, /upload|multer|formidable|busboy/gi, this, filePath, () =>
          "Validate uploads by MIME type AND magic bytes, not just extension. Use the 'file-type' package."
        );
      }
      return [];
    },
  },
  {
    id: "VC039", title: "Missing Dependency Lock File", severity: "medium", category: "Supply Chain",
    description: "Without a lockfile, dependency versions are unpinned and vulnerable to supply chain attacks.",
    check(content, filePath) {
      if (!filePath.endsWith(".gitignore")) return [];
      if (/package-lock\.json|pnpm-lock\.yaml|yarn\.lock/i.test(content)) {
        return findMatches(content, /(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock)/gi, this, filePath, () =>
          "Remove the lockfile from .gitignore. Lockfiles should be committed."
        );
      }
      return [];
    },
  },
  {
    id: "VC040", title: "Exposed .git Directory via Web Server", severity: "critical", category: "Information Leakage",
    description: "Web server configs that don't block .git access expose your entire source code and history.",
    check(content, filePath) {
      if (!filePath.match(/(?:nginx|apache|httpd|caddy|\.htaccess|vercel\.json|netlify\.toml|server\.[jt]s)/i)) return [];
      if (/(?:static|serve|express\.static|serveStatic|public)/i.test(content)) {
        if (!/\.git|dotfiles|hidden/i.test(content)) {
          return findMatches(content, /(?:static|serve|express\.static|serveStatic)\s*\(/g, this, filePath, () =>
            "Block access to .git in your static server config. For Express: app.use('/.git', (req, res) => res.status(403).end())"
          );
        }
      }
      return [];
    },
  },
  {
    id: "VC041", title: "Potential Server-Side Request Forgery (SSRF)", severity: "critical", category: "Injection",
    description: "Fetching URLs from user input without validation allows access to internal services and cloud metadata.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock")) return [];
      if (/allowedHosts|allowedDomains|allowedUrls|safeDomain|whitelist|urlValidator|isAllowedUrl/i.test(content)) return [];
      const patterns = [
        /(?:fetch|axios\.get|axios\.post|axios|got|request|http\.get|https\.get)\s*\(\s*(?:req\.(?:body|query|params)|body|input|params|args)\./gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Validate URLs against an allowlist. Block internal IPs: 127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.169.254."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC042", title: "Mass Assignment Vulnerability", severity: "high", category: "Authorization",
    description: "Spreading request body directly into database models allows attackers to set fields they shouldn't (isAdmin, role).",
    check(content, filePath) {
      if (!/(?:\/api\/|routes?\/|controllers?\/|server\.|handler)/i.test(filePath)) return [];
      if (/pick\(|omit\(|allowedFields|sanitize|whitelist|permit|strong_params/i.test(content)) return [];
      const patterns = [
        /Object\.assign\s*\(\s*(?:user|account|profile|record|doc|model|entity)[^,]*,\s*(?:req\.body|body|input|data)\s*\)/gi,
        /(?:create|update|insert|save|findOneAndUpdate|updateOne|upsert)\s*\(\s*\{[^}]*\.\.\.(?:req\.body|body|input|data)/gi,
        /(?:create|insert|save)\s*\(\s*(?:req\.body|body)\s*\)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Never pass req.body directly to DB. Pick allowed fields: const { name, email } = req.body;"
        ));
      }
      return matches;
    },
  },
  {
    id: "VC043", title: "Timing-Unsafe Secret Comparison", severity: "medium", category: "Cryptography",
    description: "Using === to compare secrets leaks info via timing side-channels.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock")) return [];
      if (/timingSafeEqual|constantTimeEqual|safeCompare|secureCompare/i.test(content)) return [];
      const patterns = [
        /(?:token|secret|hash|digest|signature|hmac|apiKey|api_key)\s*(?:===|!==)\s*(?:req\.|body\.|params\.|query\.|input)/gi,
        /(?:req\.|body\.|params\.|query\.|input)[\w.]*(?:token|secret|hash|digest|signature|hmac)\s*(?:===|!==)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Use crypto.timingSafeEqual() for comparing secrets."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC044", title: "Potential Log Injection", severity: "medium", category: "Injection",
    description: "Logging unsanitized user input allows attackers to forge log entries.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock")) return [];
      if (!/(?:\/api\/|routes?\/|controllers?\/|server\.|middleware|handler)/i.test(filePath)) return [];
      if (/sanitize|escape|JSON\.stringify|replace.*\\n/i.test(content)) return [];
      const patterns = [
        /console\.(?:log|warn|error|info)\s*\([^)]*(?:req\.body|req\.query|req\.params|req\.headers)\s*\)/gi,
        /(?:logger|log)\.(?:info|warn|error|debug)\s*\([^)]*(?:req\.body|req\.query|req\.params)\s*\)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Sanitize user input before logging. Use JSON.stringify() or a structured logger."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC045", title: "Weak Password Requirements", severity: "high", category: "Authentication",
    description: "Registration or password endpoints without minimum length/complexity validation allow weak passwords.",
    check(content, filePath) {
      if (!/(?:password|passwd|pwd)/i.test(content)) return [];
      if (!/(?:register|signup|sign.up|createUser|changePassword|resetPassword)/i.test(content) && !/(?:\/api\/|routes?\/|controllers?\/)/i.test(filePath)) return [];
      if (/(?:password|pwd).*(?:\.length|minLength|minlength)\s*(?:>=?|<|>)\s*\d|zxcvbn|password-validator|isStrongPassword/i.test(content)) return [];
      const has = /(?:password|pwd)\s*[:=]\s*(?:req\.body|body|input|params|args)\./i.test(content);
      if (!has) return [];
      return findMatches(content, /(?:password|pwd)\s*[:=]\s*(?:req\.body|body|input|params|args)\./gi, this, filePath, () =>
        "Enforce minimum password requirements: at least 8 characters. Use zxcvbn for strength estimation."
      );
    },
  },
  {
    id: "VC046", title: "Session Fixation Risk", severity: "high", category: "Authentication",
    description: "Not regenerating session IDs after login allows session fixation attacks.",
    check(content, filePath) {
      if (!/(?:login|signin|authenticate)/i.test(content) || !/session/i.test(content)) return [];
      if (/regenerate|destroy.*create|rotateSession/i.test(content)) return [];
      if (!/(?:login|signin|authenticate)\s*(?:=|:|\()/i.test(content)) return [];
      return findMatches(content, /(?:login|signin|authenticate)\s*(?:=|:|\()/gi, this, filePath, () =>
        "Regenerate session ID after login: req.session.regenerate()."
      );
    },
  },
  {
    id: "VC047", title: "Login Without Brute Force Protection", severity: "high", category: "Authentication",
    description: "Login endpoints without rate limiting or lockout are vulnerable to brute force attacks.",
    check(content, filePath) {
      if (!/(?:login|signin|auth)/i.test(filePath) && !/(?:login|signin|authenticate).*(?:post|handler)/i.test(content)) return [];
      if (!/(?:password|credential)/i.test(content)) return [];
      if (/rate.?limit|throttle|lockout|maxAttempts|failedAttempts|brute|express-brute|slowDown/i.test(content)) return [];
      return findMatches(content, /\.(post|handler)\s*\([^)]*(?:login|signin|auth)/gi, this, filePath, () =>
        "Add brute force protection: rate limiting, progressive delays, or account lockout."
      );
    },
  },
  {
    id: "VC048", title: "Potential NoSQL Injection", severity: "critical", category: "Injection",
    description: "Unsanitized user input in MongoDB queries allows bypassing auth and extracting data.",
    check(content, filePath) {
      if (!/(?:mongo|mongoose|findOne|findById|collection|aggregate)/i.test(content)) return [];
      if (/sanitize|escape|mongo-sanitize|express-mongo-sanitize|typeof.*===.*string/i.test(content)) return [];
      const patterns = [
        /\.find(?:One)?\s*\(\s*(?:req\.body|body|input|params)\s*\)/gi,
        /\.find(?:One)?\s*\(\s*\{[^}]*:\s*(?:req\.body|body|input|params)\./gi,
        /\$where\s*:\s*(?!["'`])/g,
        /\.(?:findOne|findById|deleteOne|updateOne|findOneAndUpdate)\s*\(\s*\{[^}]*:\s*(?:req\.(?:body|query|params))\./gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Sanitize MongoDB inputs: use express-mongo-sanitize and validate types."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC049", title: "Database Credentials in Config File", severity: "critical", category: "Secrets",
    description: "DB connection strings with credentials in committed config files expose them to anyone with repo access.",
    check(content, filePath) {
      if (filePath.endsWith(".example") || filePath.endsWith(".template") || filePath.match(/\.env/)) return [];
      if (!filePath.match(/(?:config|setting|database|db|knexfile|sequelize|drizzle|prisma)/i) && !filePath.match(/\.(json|yaml|yml|toml|js|ts)$/)) return [];
      const patterns = [
        /(?:host|server|database|db).*(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{3,}["'`]/gi,
        /(?:connection|database|db).*(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move database credentials to environment variables."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC050", title: "Database Connection Without SSL/TLS", severity: "high", category: "Configuration",
    description: "DB connections without SSL transmit credentials and data in plaintext.",
    check(content, filePath) {
      if (!/(?:createConnection|createPool|createClient|connect|new.*Client|knex|sequelize|drizzle)/i.test(content)) return [];
      if (!/(?:postgres|mysql|mariadb|pg|mongo)/i.test(content)) return [];
      const patterns = [/ssl\s*:\s*false/gi, /sslmode\s*[:=]\s*["'`]?disable["'`]?/gi, /rejectUnauthorized\s*:\s*false/gi];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Enable SSL/TLS for database connections: { ssl: { rejectUnauthorized: true } }."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC051", title: "GraphQL Introspection Enabled in Production", severity: "medium", category: "Information Leakage",
    description: "GraphQL introspection exposes your entire API schema to attackers.",
    check(content, filePath) {
      if (!/graphql/i.test(content) && !/graphql/i.test(filePath)) return [];
      const matches = [];
      if (/introspection\s*:\s*true/i.test(content)) {
        matches.push(...findMatches(content, /introspection\s*:\s*true/gi, this, filePath, () =>
          "Disable introspection in production: introspection: process.env.NODE_ENV !== 'production'."
        ));
      }
      if (/(?:ApolloServer|GraphQLServer|createYoga)\s*\(/i.test(content) && !/introspection/i.test(content)) {
        matches.push(...findMatches(content, /(?:ApolloServer|GraphQLServer|createYoga)\s*\(/gi, this, filePath, () =>
          "Explicitly disable introspection in production."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC052", title: "Missing Request Body Size Limit", severity: "medium", category: "Availability",
    description: "Servers without body size limits are vulnerable to DoS via oversized payloads.",
    check(content, filePath) {
      if (!/(?:server|app|index|main)\.[jt]sx?$/.test(filePath)) return [];
      if (!/(?:express|hono|fastify|koa)/i.test(content)) return [];
      const matches = [];
      if (/express\.json\s*\(\s*\)/g.test(content)) {
        matches.push(...findMatches(content, /express\.json\s*\(\s*\)/g, this, filePath, () =>
          "Set body size limit: express.json({ limit: '1mb' })."
        ));
      }
      if (/bodyParser\.json\s*\(\s*\)/g.test(content)) {
        matches.push(...findMatches(content, /bodyParser\.json\s*\(\s*\)/g, this, filePath, () =>
          "Set body size limit: bodyParser.json({ limit: '1mb' })."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC053", title: "Hardcoded IP or Host Allowlist", severity: "medium", category: "Configuration",
    description: "Hardcoded IPs in allowlists are brittle; use environment variables.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock") || filePath.match(/\.(md|txt)$/)) return [];
      const patterns = [
        /(?:allowedIPs|allowed_ips|whitelist|allowlist|trustedHosts)\s*[:=]\s*\[\s*["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move IP allowlists to environment variables: process.env.ALLOWED_IPS?.split(',')."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC054", title: "Sensitive Data in localStorage", severity: "high", category: "Secrets",
    description: "Tokens/passwords in localStorage are accessible to any XSS attack. Use httpOnly cookies.",
    check(content, filePath) {
      if (!filePath.match(/\.(jsx?|tsx?|vue|svelte)$/)) return [];
      const patterns = [
        /localStorage\.setItem\s*\(\s*["'`](?:token|access_token|auth_token|jwt|session|refresh_token|api_key|password|secret)/gi,
        /localStorage\s*\[\s*["'`](?:token|access_token|auth_token|jwt|session|refresh_token|api_key|password|secret)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Use httpOnly cookies instead of localStorage for tokens/secrets."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC055", title: "Source Maps Exposed in Production", severity: "medium", category: "Information Leakage",
    description: "Source map files in production expose original source code.",
    check(content, filePath) {
      if (!filePath.match(/(?:webpack|vite|rollup|next)\.config|tsconfig/i)) return [];
      const matches = [];
      if (/(?:sourceMap|source-map|sourcemap)\s*[:=]\s*true/i.test(content) && !/process\.env\.NODE_ENV|NODE_ENV|production/i.test(content)) {
        matches.push(...findMatches(content, /(?:sourceMap|source-map|sourcemap)\s*[:=]\s*true/gi, this, filePath, () =>
          "Disable source maps in production: sourceMap: process.env.NODE_ENV !== 'production'."
        ));
      }
      if (/productionSourceMap\s*:\s*true/i.test(content)) {
        matches.push(...findMatches(content, /productionSourceMap\s*:\s*true/gi, this, filePath, () =>
          "Set productionSourceMap: false."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC056", title: "Clickjacking — Missing X-Frame-Options", severity: "medium", category: "Configuration",
    description: "Without X-Frame-Options, your page can be embedded in attacker iframes for clickjacking.",
    check(content, filePath) {
      if (filePath.match(/\.(html|htm)$/) && !/X-Frame-Options|frame-ancestors/i.test(content)) {
        return [{ rule: "VC056", title: this.title, severity: "medium", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: 'Add <meta http-equiv="X-Frame-Options" content="DENY">.' }];
      }
      if (/(?:server|app|index|main)\.[jt]sx?$/.test(filePath) && /(?:express|hono|fastify|koa)/i.test(content) && !/X-Frame-Options|frame-ancestors|helmet/i.test(content)) {
        return findMatches(content, /(?:express|hono|fastify|koa)\s*\(/gi, this, filePath, () =>
          "Add X-Frame-Options: DENY header. Or use helmet: app.use(helmet())."
        );
      }
      return [];
    },
  },
  {
    id: "VC057", title: "Overly Permissive IAM/Cloud Permissions", severity: "critical", category: "Authorization",
    description: "Wildcard (*) permissions in IAM/Terraform violate least privilege.",
    check(content, filePath) {
      if (!filePath.match(/\.(tf|hcl|json|yaml|yml)$/) && !filePath.match(/(?:iam|policy|role|permission)/i)) return [];
      const patterns = [/["'`]Action["'`]\s*:\s*["'`]\*["'`]/g, /["'`]Resource["'`]\s*:\s*["'`]\*["'`]/g, /actions\s*=\s*\[\s*["'`]\*["'`]\s*\]/g, /role\s*[:=]\s*["'`]roles\/(?:owner|editor)["'`]/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Replace wildcard (*) with specific actions and resources (least privilege)."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC058", title: "Docker Container Running as Root", severity: "high", category: "Configuration",
    description: "Containers running as root give attackers full system access on escape.",
    check(content, filePath) {
      if (!filePath.match(/Dockerfile$/i)) return [];
      if (/^\s*USER\s+/m.test(content)) return [];
      return [{ rule: "VC058", title: this.title, severity: "high", category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
        fix: "Add USER directive: RUN addgroup -S app && adduser -S app -G app; USER app" }];
    },
  },
  {
    id: "VC059", title: "Docker Compose Binding to All Interfaces", severity: "medium", category: "Configuration",
    description: "Binding ports to 0.0.0.0 exposes services to the entire network.",
    check(content, filePath) {
      if (!filePath.match(/docker-compose|compose\.(yaml|yml)$/i)) return [];
      if (/ports:/i.test(content) && !/127\.0\.0\.1:/i.test(content)) {
        return findMatches(content, /^\s*-\s*["'`]?\d+:\d+["'`]?/gm, this, filePath, () =>
          "Bind to localhost: '127.0.0.1:3000:3000' instead of '3000:3000'."
        );
      }
      return [];
    },
  },
  {
    id: "VC060", title: "Weak Hashing Algorithm for Passwords", severity: "critical", category: "Cryptography",
    description: "MD5/SHA are too fast for passwords — use bcrypt, scrypt, or argon2.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes("mock")) return [];
      const patterns = [
        /(?:md5|sha1|sha256|sha512)\s*\([^)]*(?:password|passwd|pwd)/gi,
        /createHash\s*\(\s*["'`](?:md5|sha1|sha256)["'`]\).*(?:password|passwd|pwd)/gi,
        /(?:password|passwd|pwd).*createHash\s*\(\s*["'`](?:md5|sha1|sha256)["'`]\)/gi,
        /hashlib\.(?:md5|sha1|sha256)\s*\([^)]*(?:password|passwd|pwd)/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Use bcrypt, scrypt, or argon2: await bcrypt.hash(password, 12)."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC061", title: "Disabled TLS Certificate Verification", severity: "critical", category: "Cryptography",
    description: "Disabling TLS verification makes all HTTPS connections vulnerable to MITM attacks.",
    check(content, filePath) {
      const patterns = [/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["'`]?0["'`]?/g, /rejectUnauthorized\s*:\s*false/g, /ssl_verify\s*[:=]\s*false/gi, /InsecureSkipVerify\s*:\s*true/g, /PYTHONHTTPSVERIFY\s*[:=]\s*["'`]?0["'`]?/g];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Never disable TLS verification in production. Fix the root cause: install correct CA certificates."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC062", title: "Hardcoded Encryption Key or IV", severity: "critical", category: "Cryptography",
    description: "Hardcoded encryption keys/IVs can be extracted to decrypt all data.",
    check(content, filePath) {
      if (filePath.endsWith(".example") || filePath.endsWith(".template") || filePath.includes("test")) return [];
      const patterns = [
        /(?:encryption_key|encryptionKey|cipher_key|cipherKey|aes_key|AES_KEY|ENCRYPTION_KEY)\s*[:=]\s*["'`][^"'`]{8,}["'`]/g,
        /createCipher(?:iv)?\s*\(\s*["'`][^"'`]+["'`]\s*,\s*["'`][^"'`]+["'`]/g,
        /(?:key|iv|nonce)\s*[:=]\s*Buffer\.from\s*\(\s*["'`][^"'`]{8,}["'`]/gi,
        /(?:iv|nonce|initialVector)\s*[:=]\s*["'`][^"'`]{8,}["'`]/gi,
      ];
      const matches = [];
      for (const p of patterns) {
        matches.push(...findMatches(content, p, this, filePath, () =>
          "Move encryption keys to env vars. Generate IVs randomly: crypto.randomBytes(16). Never reuse IVs."
        ));
      }
      return matches;
    },
  },
  {
    id: "VC063", title: "Unsanitized dangerouslySetInnerHTML", severity: "critical", category: "Injection",
    description: "Using dangerouslySetInnerHTML without DOMPurify enables XSS attacks.",
    check(content, filePath) {
      if (!filePath.match(/\.(jsx|tsx)$/)) return [];
      if (!/dangerouslySetInnerHTML/i.test(content)) return [];
      if (/DOMPurify|sanitize|purify|xss|sanitizeHtml/i.test(content)) return [];
      return findMatches(content, /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g, this, filePath, () =>
        "Sanitize: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}."
      );
    },
  },
  {
    id: "VC064", title: "Next.js Server Action Without Auth", severity: "high", category: "Authorization",
    description: "Server Actions ('use server') are public endpoints. Without auth checks, anyone can call them.",
    check(content, filePath) {
      if (!filePath.match(/\.(jsx?|tsx?)$/)) return [];
      if (!/["']use server["']/i.test(content)) return [];
      if (/getServerSession|auth\(\)|currentUser|getUser|requireAuth|clerk|getAuth/i.test(content)) return [];
      if (/export\s+async\s+function/i.test(content)) {
        return findMatches(content, /export\s+async\s+function\s+\w+/g, this, filePath, () =>
          "Add auth to Server Actions: const session = await getServerSession(); if (!session) throw new Error('Unauthorized');"
        );
      }
      return [];
    },
  },
  {
    id: "VC065", title: "Unprotected Next.js API Route", severity: "high", category: "Authorization",
    description: "Next.js API routes without authentication can be called by anyone.",
    check(content, filePath) {
      if (!filePath.match(/\/api\/.*\.(jsx?|tsx?)$/) && !filePath.match(/\/app\/api\/.*route\.(jsx?|tsx?)$/)) return [];
      if (/health|status|public|webhook/i.test(filePath)) return [];
      if (/getServerSession|auth\(\)|currentUser|requireAuth|clerk|getAuth|verifyToken|middleware/i.test(content)) return [];
      if (/export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)/i.test(content)) {
        return findMatches(content, /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)/g, this, filePath, () =>
          "Add auth to API routes: const session = await getServerSession(authOptions); if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });"
        );
      }
      return [];
    },
  },
  {
    id: "VC066", title: "Secret Used in Client Component", severity: "critical", category: "Secrets",
    description: "process.env without NEXT_PUBLIC_ in 'use client' components exposes server secrets in browser bundles.",
    check(content, filePath) {
      if (!filePath.match(/\.(jsx?|tsx?)$/)) return [];
      if (!/["']use client["']/i.test(content)) return [];
      if (/process\.env\.(?!NEXT_PUBLIC_)[A-Z_]{3,}/g.test(content)) {
        return findMatches(content, /process\.env\.(?!NEXT_PUBLIC_)[A-Z_]{3,}/g, this, filePath, () =>
          "Server env vars aren't available in client components. Move this logic to a Server Component or API route."
        );
      }
      return [];
    },
  },
  {
    id: "VC067", title: "Insecure Deep Link Handling", severity: "high", category: "Injection",
    description: "Deep links without URL validation can be exploited for phishing or unauthorized actions.",
    check(content, filePath) {
      if (!/(?:Linking|DeepLinking|deep.?link|handleURL|openURL)/i.test(content)) return [];
      if (/allowedSchemes|allowedHosts|validateURL|isAllowedURL|whitelist/i.test(content)) return [];
      const patterns = [/Linking\.addEventListener\s*\([^)]*(?:url|link)/gi, /Linking\.getInitialURL\s*\(\)/g, /handleOpenURL|handleDeepLink/gi];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Validate deep link URLs against an allowlist before navigating.")); }
      return matches;
    },
  },
  {
    id: "VC068", title: "Sensitive Data in AsyncStorage", severity: "high", category: "Secrets",
    description: "AsyncStorage is unencrypted. Tokens/passwords stored there are readable by other apps.",
    check(content, filePath) {
      if (!/AsyncStorage/i.test(content)) return [];
      return findMatches(content, /AsyncStorage\.setItem\s*\(\s*["'`](?:token|access_token|auth_token|jwt|session|refresh_token|api_key|password|secret)/gi, this, filePath, () =>
        "Use react-native-keychain or expo-secure-store instead of AsyncStorage for sensitive data."
      );
    },
  },
  {
    id: "VC069", title: "Missing Certificate Pinning", severity: "medium", category: "Cryptography",
    description: "Mobile apps without SSL certificate pinning are vulnerable to MITM via rogue CAs.",
    check(content, filePath) {
      if (!/(?:react.native|expo|mobile)/i.test(filePath) && !/React.*Native|expo/i.test(content)) return [];
      if (!/axios\.create|new\s+(?:HttpClient|ApiClient)/i.test(content)) return [];
      if (/pinning|certificate|cert|ssl|TrustKit|react-native-ssl-pinning/i.test(content)) return [];
      return findMatches(content, /axios\.create|new\s+(?:HttpClient|ApiClient)/gi, this, filePath, () =>
        "Add SSL certificate pinning: use react-native-ssl-pinning or TrustKit."
      );
    },
  },
  {
    id: "VC070", title: "Android App Debuggable", severity: "high", category: "Configuration",
    description: "android:debuggable='true' allows debugger attachment and memory inspection.",
    check(content, filePath) {
      if (!filePath.match(/AndroidManifest\.xml$/i)) return [];
      return findMatches(content, /android:debuggable\s*=\s*["']true["']/gi, this, filePath, () =>
        "Remove android:debuggable='true'. Use build variants for debug builds."
      );
    },
  },
  {
    id: "VC071", title: "Django DEBUG Mode Enabled", severity: "critical", category: "Configuration",
    description: "DEBUG=True exposes source code, queries, and env vars in error pages.",
    check(content, filePath) {
      if (!filePath.match(/settings\.py$/i)) return [];
      if (/os\.environ|env\(|config\(|getenv/i.test(content)) return [];
      return findMatches(content, /^\s*DEBUG\s*=\s*True/gm, this, filePath, () =>
        "Use env var: DEBUG = os.environ.get('DEBUG', 'False') == 'True'."
      );
    },
  },
  {
    id: "VC072", title: "Flask Secret Key Hardcoded", severity: "critical", category: "Secrets",
    description: "Hardcoded secret_key allows forging sessions and CSRF tokens.",
    check(content, filePath) {
      if (!filePath.match(/\.py$/)) return [];
      if (/os\.environ|env\(|getenv/i.test(content)) return [];
      const patterns = [/(?:app\.)?secret_key\s*=\s*["'`][^"'`]{3,}["'`]/g, /(?:app\.config)\s*\[\s*["']SECRET_KEY["']\s*\]\s*=\s*["'`][^"'`]{3,}["'`]/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use env var: app.secret_key = os.environ['SECRET_KEY'].")); }
      return matches;
    },
  },
  {
    id: "VC073", title: "Unsafe Pickle Deserialization", severity: "critical", category: "Injection",
    description: "pickle.loads() on untrusted data allows arbitrary code execution.",
    check(content, filePath) {
      if (!filePath.match(/\.py$/)) return [];
      if (/restricted_loads|SafeUnpickler|safe_load|yaml\.safe_load/i.test(content)) return [];
      const patterns = [/pickle\.loads?\s*\(/g, /cPickle\.loads?\s*\(/g, /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Never unpickle untrusted data. Use JSON or yaml.safe_load().")); }
      return matches;
    },
  },
  {
    id: "VC074", title: "CSRF Protection Disabled", severity: "high", category: "Authorization",
    description: "@csrf_exempt allows forged cross-site requests.",
    check(content, filePath) {
      if (!filePath.match(/\.py$/)) return [];
      return findMatches(content, /@csrf_exempt/g, this, filePath, () =>
        "Remove @csrf_exempt. Use CSRF tokens or token-based auth (JWT) for APIs."
      );
    },
  },
  {
    id: "VC075", title: "GitHub Actions Script Injection", severity: "critical", category: "Injection",
    description: "${{ github.event.* }} in run: steps allows shell command injection via PR titles/issue bodies.",
    check(content, filePath) {
      if (!filePath.match(/\.github\/workflows\/.*\.(yml|yaml)$/i)) return [];
      const patterns = [
        /run:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)\.(?:title|body|message)/gi,
        /run:.*\$\{\{\s*github\.event\.(?:inputs|head_ref|base_ref)/gi,
      ];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Pass as env var: env: TITLE: ${{ github.event.issue.title }}, then use $TITLE.")); }
      return matches;
    },
  },
  {
    id: "VC076", title: "Hardcoded Secrets in CI Config", severity: "critical", category: "Secrets",
    description: "Tokens/keys in workflow files are visible to anyone with repo access.",
    check(content, filePath) {
      if (!filePath.match(/\.github\/workflows\/|\.gitlab-ci|Jenkinsfile|\.circleci|bitbucket-pipelines/i)) return [];
      const patterns = [
        /(?:password|token|key|secret|api_key|apikey)\s*[:=]\s*["'`][A-Za-z0-9+/=_-]{20,}["'`]/gi,
        /(?:DOCKER_PASSWORD|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|GH_TOKEN)\s*[:=]\s*["'`][^"'`$]+["'`]/gi,
      ];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use repository secrets: ${{ secrets.MY_TOKEN }}.")); }
      return matches;
    },
  },
  {
    id: "VC077", title: "CORS Wildcard in Serverless Config", severity: "high", category: "Configuration",
    description: "Access-Control-Allow-Origin: * in serverless configs allows any site to call your API.",
    check(content, filePath) {
      if (!filePath.match(/serverless\.(yml|yaml)|vercel\.json|netlify\.toml|amplify\.yml/i)) return [];
      return findMatches(content, /(?:Access-Control-Allow-Origin|allowOrigin|cors).*['"]\*['"]/gi, this, filePath, () =>
        "Replace wildcard with specific origins: allowOrigin: ['https://yourdomain.com']."
      );
    },
  },
  {
    id: "VC078", title: "Kubernetes Privileged Container", severity: "critical", category: "Configuration",
    description: "privileged: true in k8s gives full host access, making container escapes trivial.",
    check(content, filePath) {
      if (!filePath.match(/\.(yaml|yml)$/) || !/(?:kind|apiVersion|container)/i.test(content)) return [];
      const patterns = [/privileged\s*:\s*true/g, /runAsUser\s*:\s*0\b/g, /runAsNonRoot\s*:\s*false/g, /allowPrivilegeEscalation\s*:\s*true/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Set: privileged: false, runAsNonRoot: true, allowPrivilegeEscalation: false.")); }
      return matches;
    },
  },
  {
    id: "VC079", title: "JWT Algorithm Confusion (alg:none)", severity: "critical", category: "Authentication",
    description: "Accepting 'none' as JWT algorithm allows forging tokens by removing signatures.",
    check(content, filePath) {
      if (!/jwt|jsonwebtoken|jose/i.test(content)) return [];
      const matches = [];
      if (/algorithms\s*:\s*\[.*["']none["']/gi.test(content)) {
        matches.push(...findMatches(content, /algorithms\s*:\s*\[.*["']none["']/gi, this, filePath, () => "Never allow algorithm 'none'. Specify: algorithms: ['RS256']."));
      }
      if (/jwt\.verify\s*\(/g.test(content) && !/algorithms/i.test(content)) {
        matches.push(...findMatches(content, /jwt\.verify\s*\(/g, this, filePath, () => "Specify algorithms in jwt.verify: { algorithms: ['HS256'] }."));
      }
      return matches;
    },
  },
  {
    id: "VC080", title: "Potential ReDoS", severity: "high", category: "Availability",
    description: "Nested quantifiers like (a+)+ cause catastrophic backtracking.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      const patterns = [/new\s+RegExp\s*\(\s*["'`].*\([^)]*[+*]\)[+*{]/g, /\/.*\([^)]*[+*]\)[+*{].*\//g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Avoid nested quantifiers. Use the 're2' library.")); }
      return matches;
    },
  },
  {
    id: "VC081", title: "XML External Entity (XXE)", severity: "critical", category: "Injection",
    description: "XML parsers processing external entities allow file reads and SSRF.",
    check(content, filePath) {
      if (!/xml|parseXML|DOMParser|etree|lxml/i.test(content)) return [];
      if (/noent.*false|resolveExternals.*false|defusedxml|disallow-doctype-decl/i.test(content)) return [];
      const patterns = [/\.parseXML\s*\(/g, /new\s+DOMParser\s*\(\)/g, /etree\.parse\s*\(/g, /SAXParserFactory/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Disable external entities. Use defusedxml (Python).")); }
      return matches;
    },
  },
  {
    id: "VC082", title: "Server-Side Template Injection", severity: "critical", category: "Injection",
    description: "Rendering templates from user input allows arbitrary code execution.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      const patterns = [/render_template_string\s*\(\s*(?!["'`])/g, /Template\s*\(\s*(?:req\.|body\.|input)/gi, /nunjucks\.renderString\s*\(\s*(?:req\.|body\.|input)/gi, /ejs\.render\s*\(\s*(?:req\.|body\.|input)/gi];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use pre-defined templates with data as context variables.")); }
      return matches;
    },
  },
  {
    id: "VC083", title: "Insecure Java Deserialization", severity: "critical", category: "Injection",
    description: "ObjectInputStream.readObject() allows arbitrary code execution via gadget chains.",
    check(content, filePath) {
      if (!filePath.match(/\.java$|\.kt$/)) return [];
      if (/ValidatingObjectInputStream|ObjectInputFilter|SerialKiller/i.test(content)) return [];
      const patterns = [/ObjectInputStream\s*\(/g, /\.readObject\s*\(\)/g, /XMLDecoder\s*\(/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use ValidatingObjectInputStream or JSON instead.")); }
      return matches;
    },
  },
  {
    id: "VC084", title: "Missing Subresource Integrity (SRI)", severity: "medium", category: "Configuration",
    description: "External scripts without integrity= can be tampered with if CDN is compromised.",
    check(content, filePath) {
      if (!filePath.match(/\.(html|htm|jsx|tsx)$/)) return [];
      const matches = [];
      const re = /<script\s+[^>]*src\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi;
      let m;
      while ((m = re.exec(content)) !== null) {
        if (!m[0].includes("integrity")) {
          const lineNum = content.substring(0, m.index).split("\n").length;
          matches.push({ rule: "VC084", title: this.title, severity: "medium", category: "Configuration", file: filePath, line: lineNum, snippet: getSnippet(content, lineNum), fix: 'Add integrity and crossorigin attributes.' });
        }
      }
      return matches;
    },
  },
  {
    id: "VC085", title: "Exposed Admin or Debug Route", severity: "high", category: "Information Leakage",
    description: "Routes like /admin, /debug without auth expose sensitive controls.",
    check(content, filePath) {
      if (!/(?:\/api\/|routes?\/|server\.|app\.|index\.[jt]s)/i.test(filePath)) return [];
      if (/auth|requireAuth|isAdmin|middleware.*admin/i.test(content)) return [];
      return findMatches(content, /[.'"]\s*(?:get|use|all)\s*\(\s*["'`]\/(?:admin|debug|_debug|phpinfo|actuator|graphiql|playground)["'`]/gi, this, filePath, () =>
        "Protect admin/debug routes with auth middleware. Disable in production."
      );
    },
  },
  {
    id: "VC086", title: "Insecure WebSocket (ws://)", severity: "medium", category: "Configuration",
    description: "ws:// transmits data in plaintext. Use wss:// for encrypted connections.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      return findMatches(content, /new\s+WebSocket\s*\(\s*["'`]ws:\/\//g, this, filePath, () => "Use wss:// instead of ws://.");
    },
  },
  {
    id: "VC087", title: "Missing HSTS Header", severity: "medium", category: "Configuration",
    description: "Without HSTS, browsers allow HTTPS-to-HTTP downgrade attacks.",
    check(content, filePath) {
      if (!/(?:server|app|index|main)\.[jt]sx?$/.test(filePath)) return [];
      if (!/(?:express|hono|fastify|koa)/i.test(content)) return [];
      if (/Strict-Transport-Security|hsts|helmet/i.test(content)) return [];
      return findMatches(content, /(?:express|hono|fastify|koa)\s*\(/gi, this, filePath, () =>
        "Add HSTS: res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')."
      );
    },
  },
  {
    id: "VC088", title: "Sensitive Data in URL Parameters", severity: "high", category: "Information Leakage",
    description: "Passwords/tokens in URLs are exposed in logs, history, and referrer headers.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      const patterns = [/\?\s*(?:password|token|secret|api_key|apiKey|access_token)\s*=/gi, /[&?](?:password|token|secret|api_key)\s*=\s*\$\{/gi];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use Authorization header or POST body instead.")); }
      return matches;
    },
  },
  {
    id: "VC089", title: "File Download Missing Content-Disposition", severity: "medium", category: "Configuration",
    description: "Downloads without Content-Disposition may render inline, enabling XSS.",
    check(content, filePath) {
      if (!/(?:download|sendFile|send_file|createReadStream)/i.test(content)) return [];
      if (!/(?:\/api\/|routes?\/|server\.|handler)/i.test(filePath)) return [];
      if (/Content-Disposition|attachment/i.test(content)) return [];
      return findMatches(content, /(?:sendFile|send_file|createReadStream|\.pipe)\s*\(/gi, this, filePath, () =>
        "Set Content-Disposition: attachment header on downloads."
      );
    },
  },
  {
    id: "VC090", title: "Open Redirect via Host Header", severity: "high", category: "Injection",
    description: "Using req.headers.host for redirects allows attackers to inject malicious hosts.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      if (/req\.headers\.host|req\.get\s*\(\s*["']host["']\)/i.test(content) && /redirect|location/i.test(content)) {
        return findMatches(content, /req\.headers\.host|req\.get\s*\(\s*["']host["']\)/gi, this, filePath, () =>
          "Don't use req.headers.host for redirects. Use a hardcoded domain or env var."
        );
      }
      return [];
    },
  },
  {
    id: "VC091", title: "Race Condition (TOCTOU)", severity: "high", category: "Authorization",
    description: "Check-then-act patterns are vulnerable to state changes between check and action.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      const patterns = [/(?:existsSync|exists)\s*\([^)]+\)[\s\S]{0,50}(?:writeFileSync|writeFile|unlinkSync)\s*\(/g, /os\.path\.exists\s*\([^)]+\)[\s\S]{0,50}open\s*\(/g];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use atomic operations: fs.open with 'wx' flag.")); }
      return matches;
    },
  },
  {
    id: "VC092", title: "Unsafe Object Spread from User Input", severity: "medium", category: "Injection",
    description: "Spreading req.body can copy __proto__ or constructor properties (prototype pollution).",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      if (/omit.*__proto__|sanitize|pick\(/i.test(content)) return [];
      const patterns = [/Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.(?:body|query|params)|body|input)\s*\)/gi, /\{\s*\.\.\.(?:req\.(?:body|query|params)|body|input)\s*\}/gi];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Pick allowed properties explicitly.")); }
      return matches;
    },
  },
  {
    id: "VC093", title: "File Download Without Path Validation", severity: "medium", category: "Authorization",
    description: "User-controlled filenames in downloads allow directory traversal.",
    check(content, filePath) {
      if (!/(?:sendFile|download|send_file)\s*\([^)]*(?:req\.|params\.|query\.)/i.test(content)) return [];
      if (/path\.resolve|path\.normalize|realpath/i.test(content)) return [];
      return findMatches(content, /(?:sendFile|download|send_file)\s*\(/gi, this, filePath, () =>
        "Validate: const safe = path.resolve(DIR, name); if (!safe.startsWith(DIR)) throw Error();"
      );
    },
  },
  {
    id: "VC094", title: "Potential Command Injection", severity: "critical", category: "Injection",
    description: "User input in shell commands allows arbitrary command execution.",
    check(content, filePath) {
      if (filePath.includes("test")) return [];
      if (/execFile|spawn|escapeshellarg|shlex\.quote/i.test(content)) return [];
      const patterns = [/(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\+\s*(?:req\.|body\.|input|params))/gi, /os\.system\s*\(\s*(?!["'`].*["'`]\s*\))/g, /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi];
      const matches = [];
      for (const p of patterns) { matches.push(...findMatches(content, p, this, filePath, () => "Use execFile/spawn. Never concatenate user input into commands.")); }
      return matches;
    },
  },
  {
    id: "VC095", title: "Hardcoded Localhost CORS Origin", severity: "medium", category: "Configuration",
    description: "Hardcoded localhost CORS allows any local process to call your API.",
    check(content, filePath) {
      if (filePath.includes("test") || filePath.includes(".env")) return [];
      if (!/origin/i.test(content)) return [];
      return findMatches(content, /origin\s*[:=]\s*["'`]http:\/\/localhost/gi, this, filePath, () =>
        "Use env vars for CORS origins: origin: process.env.ALLOWED_ORIGIN."
      );
    },
  },
  {
    id: "VC096", title: "Unencrypted gRPC Channel", severity: "medium", category: "Configuration",
    description: "Insecure gRPC channels transmit data including credentials in plaintext.",
    check(content, filePath) {
      if (!/grpc/i.test(content)) return [];
      return findMatches(content, /(?:insecure_channel|createInsecure|grpc\.Insecure)/gi, this, filePath, () =>
        "Use encrypted channels: grpc.ssl_channel_credentials()."
      );
    },
  },
];

// ────────────────────────────────────────────
// FRAMEWORK DETECTION
// ────────────────────────────────────────────

function detectFramework(files) {
  const frameworks = new Set();
  for (const { path, content } of files) {
    if (path.match(/next\.config/i) || /from\s+["']next/i.test(content)) frameworks.add("next.js");
    if (/from\s+["']react-native/i.test(content) || path.match(/react-native\.config/i)) frameworks.add("react-native");
    else if (/from\s+["']react/i.test(content) || /import\s+React/i.test(content)) frameworks.add("react");
    if (/from\s+["']express/i.test(content) || /require\s*\(\s*["']express/i.test(content)) frameworks.add("express");
    if (/from\s+["']hono/i.test(content)) frameworks.add("hono");
    if (/from\s+["']fastify/i.test(content)) frameworks.add("fastify");
    if (/from\s+["']electron/i.test(content) || path.match(/electron/i)) frameworks.add("electron");
    if (path.match(/settings\.py$/) || /from\s+django/i.test(content)) frameworks.add("django");
    if (/from\s+flask/i.test(content) || /Flask\s*\(/i.test(content)) frameworks.add("flask");
    if (/from\s+["']vue/i.test(content) || path.match(/vue\.config/i)) frameworks.add("vue");
    if (/from\s+["']svelte/i.test(content) || path.match(/svelte\.config/i)) frameworks.add("svelte");
  }
  return [...frameworks];
}

// ────────────────────────────────────────────
// SEVERITY GRADING
// ────────────────────────────────────────────

function calculateGrade(findings, totalFiles) {
  if (findings.length === 0) {
    return { grade: "A+", score: 100, summary: "No security issues detected. Excellent!" };
  }
  let deductions = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": deductions += 15; break;
      case "high": deductions += 8; break;
      case "medium": deductions += 4; break;
      case "low": deductions += 1; break;
    }
  }
  const sizeBuffer = Math.min(Math.log2(Math.max(totalFiles, 1)) * 2, 15);
  const score = Math.max(0, Math.min(100, 100 - deductions + sizeBuffer));
  let grade, summary;
  if (score >= 95) { grade = "A+"; summary = "Excellent security posture."; }
  else if (score >= 85) { grade = "A"; summary = "Strong security with minor concerns."; }
  else if (score >= 70) { grade = "B"; summary = "Good security but some issues need attention."; }
  else if (score >= 55) { grade = "C"; summary = "Fair — several vulnerabilities should be fixed."; }
  else if (score >= 35) { grade = "D"; summary = "Poor — critical issues require immediate attention."; }
  else { grade = "F"; summary = "Failing — serious vulnerabilities present."; }
  return { grade, score: Math.round(score), summary };
}

// COMPLIANCE MAPPING
const complianceMap = {
  VC001: { owasp: "A07:2021", cwe: "CWE-798" }, VC002: { owasp: "A05:2021", cwe: "CWE-200" },
  VC003: { owasp: "A01:2021", cwe: "CWE-862" }, VC004: { owasp: "A01:2021", cwe: "CWE-284" },
  VC005: { owasp: "A08:2021", cwe: "CWE-345" }, VC006: { owasp: "A03:2021", cwe: "CWE-89" },
  VC007: { owasp: "A03:2021", cwe: "CWE-79" }, VC008: { owasp: "A04:2021", cwe: "CWE-770" },
  VC009: { owasp: "A05:2021", cwe: "CWE-942" }, VC010: { owasp: "A01:2021", cwe: "CWE-602" },
  VC011: { owasp: "A07:2021", cwe: "CWE-798" }, VC012: { owasp: "A05:2021", cwe: "CWE-200" },
  VC013: { owasp: "A01:2021", cwe: "CWE-269" }, VC014: { owasp: "A05:2021", cwe: "CWE-538" },
  VC015: { owasp: "A03:2021", cwe: "CWE-95" }, VC016: { owasp: "A01:2021", cwe: "CWE-601" },
  VC017: { owasp: "A05:2021", cwe: "CWE-614" }, VC018: { owasp: "A07:2021", cwe: "CWE-798" },
  VC019: { owasp: "A05:2021", cwe: "CWE-693" }, VC020: { owasp: "A05:2021", cwe: "CWE-1021" },
  VC021: { owasp: "A01:2021", cwe: "CWE-22" }, VC022: { owasp: "A03:2021", cwe: "CWE-79" },
  VC023: { owasp: "A08:2021", cwe: "CWE-1321" }, VC024: { owasp: "A04:2021", cwe: "CWE-770" },
  VC025: { owasp: "A03:2021", cwe: "CWE-22" }, VC026: { owasp: "A05:2021", cwe: "CWE-693" },
  VC027: { owasp: "A05:2021", cwe: "CWE-693" }, VC028: { owasp: "A07:2021", cwe: "CWE-20" },
  VC029: { owasp: "A08:2021", cwe: "CWE-20" }, VC030: { owasp: "A08:2021", cwe: "CWE-502" },
  VC031: { owasp: "A02:2021", cwe: "CWE-321" }, VC032: { owasp: "A05:2021", cwe: "CWE-319" },
  VC033: { owasp: "A05:2021", cwe: "CWE-215" }, VC034: { owasp: "A02:2021", cwe: "CWE-338" },
  VC035: { owasp: "A01:2021", cwe: "CWE-601" }, VC036: { owasp: "A04:2021", cwe: "CWE-755" },
  VC037: { owasp: "A09:2021", cwe: "CWE-209" }, VC038: { owasp: "A04:2021", cwe: "CWE-434" },
  VC039: { owasp: "A06:2021", cwe: "CWE-1104" }, VC040: { owasp: "A05:2021", cwe: "CWE-538" },
  VC041: { owasp: "A10:2021", cwe: "CWE-918" }, VC042: { owasp: "A01:2021", cwe: "CWE-915" },
  VC043: { owasp: "A02:2021", cwe: "CWE-208" }, VC044: { owasp: "A09:2021", cwe: "CWE-117" },
  VC045: { owasp: "A07:2021", cwe: "CWE-521" }, VC046: { owasp: "A07:2021", cwe: "CWE-384" },
  VC047: { owasp: "A07:2021", cwe: "CWE-307" }, VC048: { owasp: "A03:2021", cwe: "CWE-943" },
  VC049: { owasp: "A07:2021", cwe: "CWE-798" }, VC050: { owasp: "A02:2021", cwe: "CWE-319" },
  VC051: { owasp: "A05:2021", cwe: "CWE-200" }, VC052: { owasp: "A04:2021", cwe: "CWE-770" },
  VC053: { owasp: "A05:2021", cwe: "CWE-798" }, VC054: { owasp: "A07:2021", cwe: "CWE-922" },
  VC055: { owasp: "A05:2021", cwe: "CWE-540" }, VC056: { owasp: "A05:2021", cwe: "CWE-1021" },
  VC057: { owasp: "A01:2021", cwe: "CWE-269" }, VC058: { owasp: "A05:2021", cwe: "CWE-250" },
  VC059: { owasp: "A05:2021", cwe: "CWE-284" }, VC060: { owasp: "A02:2021", cwe: "CWE-328" },
  VC061: { owasp: "A02:2021", cwe: "CWE-295" }, VC062: { owasp: "A02:2021", cwe: "CWE-321" },
  VC063: { owasp: "A03:2021", cwe: "CWE-79" }, VC064: { owasp: "A01:2021", cwe: "CWE-862" },
  VC065: { owasp: "A01:2021", cwe: "CWE-862" }, VC066: { owasp: "A07:2021", cwe: "CWE-798" },
  VC067: { owasp: "A01:2021", cwe: "CWE-601" }, VC068: { owasp: "A07:2021", cwe: "CWE-922" },
  VC069: { owasp: "A02:2021", cwe: "CWE-295" }, VC070: { owasp: "A05:2021", cwe: "CWE-489" },
  VC071: { owasp: "A05:2021", cwe: "CWE-215" }, VC072: { owasp: "A07:2021", cwe: "CWE-798" },
  VC073: { owasp: "A08:2021", cwe: "CWE-502" }, VC074: { owasp: "A01:2021", cwe: "CWE-352" },
  VC075: { owasp: "A03:2021", cwe: "CWE-78" }, VC076: { owasp: "A07:2021", cwe: "CWE-798" },
  VC077: { owasp: "A05:2021", cwe: "CWE-942" }, VC078: { owasp: "A05:2021", cwe: "CWE-250" },
  VC079: { owasp: "A02:2021", cwe: "CWE-327" }, VC080: { owasp: "A04:2021", cwe: "CWE-1333" },
  VC081: { owasp: "A03:2021", cwe: "CWE-611" }, VC082: { owasp: "A03:2021", cwe: "CWE-94" },
  VC083: { owasp: "A08:2021", cwe: "CWE-502" }, VC084: { owasp: "A06:2021", cwe: "CWE-353" },
  VC085: { owasp: "A01:2021", cwe: "CWE-862" }, VC086: { owasp: "A02:2021", cwe: "CWE-319" },
  VC087: { owasp: "A05:2021", cwe: "CWE-311" }, VC088: { owasp: "A07:2021", cwe: "CWE-598" },
  VC089: { owasp: "A05:2021", cwe: "CWE-430" }, VC090: { owasp: "A01:2021", cwe: "CWE-601" },
  VC091: { owasp: "A04:2021", cwe: "CWE-367" }, VC092: { owasp: "A08:2021", cwe: "CWE-1321" },
  VC093: { owasp: "A01:2021", cwe: "CWE-22" }, VC094: { owasp: "A03:2021", cwe: "CWE-78" },
  VC095: { owasp: "A05:2021", cwe: "CWE-942" }, VC096: { owasp: "A02:2021", cwe: "CWE-319" },
};

const GRADE_PERCENTILES = { "A+": 98, "A": 90, "B": 70, "C": 45, "D": 20, "F": 5 };

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
          owasp: (complianceMap[rule.id] || {}).owasp,
          cwe: (complianceMap[rule.id] || {}).cwe,
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
    const gradeResult = calculateGrade(findings, filesToScan.length);
    const frameworks = detectFramework(filesToScan);

    return c.json({
      findings,
      filesScanned: filesToScan.length,
      duration,
      grade: gradeResult.grade,
      score: gradeResult.score,
      gradeSummary: gradeResult.summary,
      frameworks,
      totalRules: rules.length,
      percentile: GRADE_PERCENTILES[gradeResult.grade] || 50,
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
    const gradeResult = calculateGrade(findings, filesToScan.length);
    const frameworks = detectFramework(filesToScan);

    return c.json({
      findings,
      filesScanned: filesToScan.length,
      duration,
      grade: gradeResult.grade,
      score: gradeResult.score,
      gradeSummary: gradeResult.summary,
      frameworks,
      totalRules: rules.length,
      percentile: GRADE_PERCENTILES[gradeResult.grade] || 50,
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
