import type { CustomRule, Finding, RuleMatch } from "../types.js";
import { readFileContents, getSnippet } from "../utils/files.js";

// Helper to find all regex matches with line numbers
function findMatches(
  content: string,
  pattern: RegExp,
  rule: Omit<CustomRule, "check">,
  filePath: string,
  fixTemplate?: (match: RegExpExecArray) => string,
): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const lines = content.split("\n");
  let m: RegExpExecArray | null;
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);

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
      fix: fixTemplate?.(m),
    });
  }

  return matches;
}

// ────────────────────────────────────────────
// RULE DEFINITIONS
// ────────────────────────────────────────────

const hardcodedSecrets: CustomRule = {
  id: "VC001",
  title: "Hardcoded API Key or Secret",
  severity: "critical",
  category: "Secrets",
  description: "API keys, tokens, or secrets hardcoded in source code can be extracted by anyone with access to the code.",
  check(content, filePath) {
    // Skip .env.example files
    if (filePath.endsWith(".example") || filePath.endsWith(".template")) return [];

    const patterns = [
      // Generic API key patterns
      /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]/gi,
      // AWS keys
      /(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/g,
      // Stripe keys
      /(?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]{20,}/g,
      // Supabase anon/service keys (JWT format)
      /(?:supabase[_-]?(?:anon|service)[_-]?key|SUPABASE_(?:ANON|SERVICE_ROLE)_KEY)\s*[:=]\s*["'`](eyJ[a-zA-Z0-9_-]{50,})["'`]/gi,
      // OpenAI keys
      /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,
      // Generic tokens in assignments
      /(?:token|secret|password|passwd|pwd)\s*[:=]\s*["'`]([a-zA-Z0-9_\-!@#$%^&*]{12,})["'`]/gi,
      // Private keys
      /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
      // Database URLs with credentials
      /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:]+:[^@]+@[^/\s"'`]+/gi,
    ];

    const matches: RuleMatch[] = [];
    for (const pattern of patterns) {
      matches.push(
        ...findMatches(content, pattern, hardcodedSecrets, filePath, () =>
          "Move this secret to an environment variable and add it to .env (not committed to git). Use .env.example to document the required variables."
        ),
      );
    }
    return matches;
  },
};

const exposedEnvFile: CustomRule = {
  id: "VC002",
  title: "Environment File May Be Committed",
  severity: "high",
  category: "Secrets",
  description: ".env files containing secrets may be committed to version control.",
  check(content, filePath) {
    // Only applies to .env files (not .env.example)
    if (!filePath.match(/\.env(?:\.[a-z]+)?$/) || filePath.includes("example")) return [];

    const hasSecrets = /(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE_URL)\s*=/i.test(content);
    if (!hasSecrets) return [];

    return [{
      rule: "VC002",
      title: exposedEnvFile.title,
      severity: "high",
      category: "Secrets",
      file: filePath,
      line: 1,
      snippet: getSnippet(content, 1),
      fix: 'Add ".env*" to your .gitignore file and remove this file from git history with: git rm --cached ' + filePath,
    }];
  },
};

const missingAuthMiddleware: CustomRule = {
  id: "VC003",
  title: "API Route Missing Authentication",
  severity: "high",
  category: "Authentication",
  description: "API routes without authentication checks allow unauthorized access.",
  check(content, filePath) {
    // Only check API route files
    const isApiRoute = /(?:\/api\/|routes?\/|controllers?\/|endpoints?\/)/.test(filePath) ||
                       filePath.includes("server.");
    if (!isApiRoute) return [];

    // Look for route handlers without auth checks
    const routePatterns = [
      // Express/Hono style
      /\.(get|post|put|patch|delete)\s*\(\s*["'`][^"'`]+["'`]\s*,\s*(?:async\s+)?\(?(?:req|c|ctx)/gi,
      // Next.js API routes
      /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/gi,
    ];

    const authPatterns = [
      /auth/i, /session/i, /jwt/i, /bearer/i, /middleware/i,
      /getUser/i, /currentUser/i, /isAuthenticated/i, /requireAuth/i,
      /clerk/i, /supabase\.auth/i, /getServerSession/i, /getToken/i,
    ];

    const hasAuth = authPatterns.some((p) => p.test(content));
    if (hasAuth) return [];

    const matches: RuleMatch[] = [];
    for (const pattern of routePatterns) {
      matches.push(
        ...findMatches(content, pattern, missingAuthMiddleware, filePath, () =>
          "Add authentication middleware to protect this route. Check the user's session/token before processing the request."
        ),
      );
    }
    return matches;
  },
};

const supabaseNoRLS: CustomRule = {
  id: "VC004",
  title: "Supabase Client Without Row Level Security",
  severity: "critical",
  category: "Authorization",
  description: "Using Supabase with the service role key or bypassing RLS exposes all database rows to any user.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];

    // Service role key used in client-side code
    if (
      /supabase_service_role|service_role_key/i.test(content) &&
      (/["']use client["']/.test(content) || filePath.match(/\.(jsx|tsx|vue|svelte)$/))
    ) {
      matches.push(
        ...findMatches(
          content,
          /service_role/gi,
          supabaseNoRLS,
          filePath,
          () => "Never expose the service_role key in client-side code. Use the anon key with RLS policies instead.",
        ),
      );
    }

    // .rpc() or direct table access without .auth
    if (/createClient/i.test(content) && /\.from\(/.test(content)) {
      const hasRLSBypass = /\.rpc\(|auth\.admin|service_role/i.test(content);
      if (hasRLSBypass) {
        matches.push(
          ...findMatches(
            content,
            /\.rpc\(|auth\.admin/gi,
            { ...supabaseNoRLS, title: "Supabase RLS Bypass Detected" },
            filePath,
            () => "Ensure RLS policies are enabled on all tables and avoid bypassing them with service_role or admin methods in user-facing code.",
          ),
        );
      }
    }

    return matches;
  },
};

const stripeWebhookUnprotected: CustomRule = {
  id: "VC005",
  title: "Unprotected Stripe Webhook Endpoint",
  severity: "critical",
  category: "Payment Security",
  description: "Stripe webhook endpoints without signature verification allow attackers to fake payment events.",
  check(content, filePath) {
    // Only check files that reference Stripe webhooks
    if (!/stripe|webhook/i.test(content)) return [];

    const hasWebhookRoute = /webhook/i.test(filePath) ||
      /(?:post|handler).*webhook/i.test(content);
    if (!hasWebhookRoute) return [];

    // Check for signature verification
    const hasVerification = /constructEvent|verifyHeader|stripe-signature|webhook_secret/i.test(content);
    if (hasVerification) return [];

    return findMatches(
      content,
      /webhook/gi,
      stripeWebhookUnprotected,
      filePath,
      () =>
        "Verify the Stripe webhook signature using stripe.webhooks.constructEvent(body, sig, webhookSecret) to prevent forged payment events.",
    );
  },
};

const sqlInjection: CustomRule = {
  id: "VC006",
  title: "Potential SQL Injection",
  severity: "critical",
  category: "Injection",
  description: "String concatenation or template literals in SQL queries allow attackers to execute arbitrary database commands.",
  check(content, filePath) {
    const patterns = [
      // Template literals in SQL
      /(?:query|execute|raw|sql)\s*\(\s*`[^`]*\$\{/gi,
      // String concatenation in SQL
      /(?:query|execute)\s*\(\s*["'][^"']*["']\s*\+/gi,
      // Direct variable interpolation
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\s+.*\$\{(?!.*parameterized)/gi,
    ];

    const matches: RuleMatch[] = [];

    // Skip if using parameterized queries / prepared statements
    const usesParams = /\?\s*,|\$\d+|:[\w]+|\bprepare\b|\bplaceholder\b/i.test(content);
    if (usesParams) return [];

    for (const pattern of patterns) {
      matches.push(
        ...findMatches(content, pattern, sqlInjection, filePath, () =>
          "Use parameterized queries or prepared statements instead of string interpolation. Example: db.query('SELECT * FROM users WHERE id = ?', [userId])"
        ),
      );
    }
    return matches;
  },
};

const xssVulnerability: CustomRule = {
  id: "VC007",
  title: "Potential Cross-Site Scripting (XSS)",
  severity: "high",
  category: "Injection",
  description: "Rendering user input without sanitization allows attackers to inject malicious scripts.",
  check(content, filePath) {
    const patterns = [
      // React dangerouslySetInnerHTML
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
      // Direct innerHTML assignment
      /\.innerHTML\s*=\s*(?!["'`]\s*$)/gm,
      // document.write
      /document\.write\s*\(/g,
      // v-html in Vue
      /v-html\s*=/g,
      // {@html} in Svelte
      /\{@html\s/g,
    ];

    const matches: RuleMatch[] = [];
    for (const pattern of patterns) {
      matches.push(
        ...findMatches(content, pattern, xssVulnerability, filePath, () =>
          "Sanitize user input before rendering as HTML. Use a library like DOMPurify: DOMPurify.sanitize(userInput)"
        ),
      );
    }
    return matches;
  },
};

const noRateLimiting: CustomRule = {
  id: "VC008",
  title: "API Endpoint Without Rate Limiting",
  severity: "medium",
  category: "Availability",
  description: "API endpoints without rate limiting are vulnerable to abuse and denial-of-service attacks.",
  check(content, filePath) {
    // Only check main server/app entry files
    const isEntryFile = /(?:server|app|index|main)\.[jt]sx?$/.test(filePath) ||
                        filePath.includes("middleware");
    if (!isEntryFile) return [];

    // Check if this is a server file
    const isServer = /(?:express|hono|fastify|koa|next|createServer|listen\()/i.test(content);
    if (!isServer) return [];

    // Check for rate limiting
    const hasRateLimit = /rate.?limit|throttle|express-rate-limit|@elysiajs\/rate-limit|hono.*limiter/i.test(content);
    if (hasRateLimit) return [];

    return [{
      rule: "VC008",
      title: noRateLimiting.title,
      severity: "medium",
      category: "Availability",
      file: filePath,
      line: 1,
      snippet: getSnippet(content, 1),
      fix: "Add rate limiting middleware to your server. For Express: npm install express-rate-limit. For other frameworks, check their rate limiting plugins.",
    }];
  },
};

const corsWildcard: CustomRule = {
  id: "VC009",
  title: "CORS Allows All Origins",
  severity: "medium",
  category: "Configuration",
  description: "Wildcard CORS (*) allows any website to make requests to your API, potentially exposing user data.",
  check(content, filePath) {
    const patterns = [
      /cors\(\s*\)/g, // cors() with no options = allow all
      /origin\s*:\s*["'`]\*["'`]/g,
      /["'`]Access-Control-Allow-Origin["'`]\s*,\s*["'`]\*["'`]/g,
      /origin\s*:\s*true/g,
    ];

    const matches: RuleMatch[] = [];
    for (const pattern of patterns) {
      matches.push(
        ...findMatches(content, pattern, corsWildcard, filePath, () =>
          "Restrict CORS to your specific frontend domain(s): cors({ origin: 'https://yourdomain.com' })"
        ),
      );
    }
    return matches;
  },
};

const clientSideAuth: CustomRule = {
  id: "VC010",
  title: "Client-Side Only Authorization",
  severity: "high",
  category: "Authorization",
  description: "Hiding UI elements based on roles without server-side checks lets attackers bypass restrictions using DevTools.",
  check(content, filePath) {
    // Only check frontend component files
    if (!filePath.match(/\.(jsx|tsx|vue|svelte)$/)) return [];

    const matches: RuleMatch[] = [];

    // Pattern: conditional rendering based on role/admin without server check
    const rolePatterns = [
      /\{.*(?:isAdmin|role\s*===?\s*["'`]admin["'`]|user\.role).*&&/gi,
      /v-if\s*=\s*["'`].*(?:isAdmin|role\s*===?\s*'admin')/gi,
    ];

    for (const pattern of rolePatterns) {
      // Only flag if the file has no server-side fetch for auth verification
      const hasServerCheck = /getServerSession|getUser|server|api\/auth|middleware/i.test(content);
      if (hasServerCheck) continue;

      matches.push(
        ...findMatches(content, pattern, clientSideAuth, filePath, () =>
          "Client-side role checks only hide UI — they don't prevent access. Always verify permissions on the server/API side too."
        ),
      );
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC011 – Secret in NEXT_PUBLIC_ env var
// ────────────────────────────────────────────

const nextPublicSecret: CustomRule = {
  id: "VC011",
  title: "Secret in NEXT_PUBLIC_ Environment Variable",
  severity: "critical",
  category: "Secrets",
  description: "NEXT_PUBLIC_ variables are exposed to the browser. Secrets placed here are visible to anyone.",
  check(content, filePath) {
    if (!filePath.match(/\.env/) && !filePath.match(/next\.config/)) return [];
    const patterns = [
      /NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=\s*.+/gi,
      /NEXT_PUBLIC_[A-Z_]*(?:SUPABASE_SERVICE|CLERK_SECRET|STRIPE_SECRET)[A-Z_]*\s*=\s*.+/gi,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, nextPublicSecret, filePath, () =>
        "Remove the NEXT_PUBLIC_ prefix. Only use NEXT_PUBLIC_ for values safe to expose in the browser."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC012 – Firebase config in client code
// ────────────────────────────────────────────

const firebaseClientConfig: CustomRule = {
  id: "VC012",
  title: "Firebase Config with API Key in Client Code",
  severity: "medium",
  category: "Configuration",
  description: "Firebase config objects in client code expose your API key. While Firebase API keys aren't secret, they should be restricted in the Firebase console.",
  check(content, filePath) {
    if (!/firebase/i.test(content)) return [];
    const patterns = [
      /firebaseConfig\s*=\s*\{[^}]*apiKey\s*:/gi,
      /initializeApp\s*\(\s*\{[^}]*apiKey\s*:/gi,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, firebaseClientConfig, filePath, () =>
        "Move Firebase config to environment variables. Restrict the API key in Firebase Console > Project Settings > API restrictions."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC013 – Supabase anon key for admin ops
// ────────────────────────────────────────────

const supabaseAnonAdmin: CustomRule = {
  id: "VC013",
  title: "Supabase Anon Key Used for Admin Operations",
  severity: "high",
  category: "Authorization",
  description: "Using the Supabase anon key for operations that require elevated privileges is insecure.",
  check(content, filePath) {
    if (!/supabase/i.test(content)) return [];
    if (!/anon/i.test(content)) return [];
    if (/service_role/i.test(content)) return [];
    const patterns = [
      /supabase[^.]*\.auth\.admin/gi,
      /supabase[^.]*\.rpc\s*\(/gi,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, supabaseAnonAdmin, filePath, () =>
        "Use the service_role key on the server side for admin operations. Never expose it to the client."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC014 – .env not in .gitignore
// ────────────────────────────────────────────

const envNotGitignored: CustomRule = {
  id: "VC014",
  title: ".env File Not in .gitignore",
  severity: "high",
  category: "Secrets",
  description: "If .env is not listed in .gitignore, secrets will be committed to version control.",
  check(content, filePath) {
    if (!filePath.endsWith(".gitignore")) return [];
    if (/\.env/i.test(content)) return [];
    return [{
      rule: "VC014", title: envNotGitignored.title, severity: "high" as const, category: "Secrets",
      file: filePath, line: 1, snippet: getSnippet(content, 1),
      fix: 'Add ".env*" to your .gitignore file to prevent committing secrets.',
    }];
  },
};

// ────────────────────────────────────────────
// VC015 – eval() / new Function()
// ────────────────────────────────────────────

const evalUsage: CustomRule = {
  id: "VC015",
  title: "Use of eval() or Function Constructor",
  severity: "high",
  category: "Injection",
  description: "eval() and new Function() execute arbitrary code, creating severe injection risks. Common in AI-generated code.",
  check(content, filePath) {
    if (filePath.includes("node_modules") || filePath.includes(".min.")) return [];
    const patterns = [
      /\beval\s*\(/g,
      /new\s+Function\s*\(/g,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, evalUsage, filePath, () =>
        "Replace eval() with JSON.parse() for data, or a proper parser for expressions. Never pass user input to eval()."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC016 – Unvalidated redirect
// ────────────────────────────────────────────

const unvalidatedRedirect: CustomRule = {
  id: "VC016",
  title: "Unvalidated Redirect",
  severity: "high",
  category: "Injection",
  description: "Redirecting users to URLs from untrusted input enables phishing attacks.",
  check(content, filePath) {
    const patterns = [
      /window\.location\s*=\s*(?!["'`]https?:\/\/)/g,
      /window\.location\.href\s*=\s*(?!["'`]https?:\/\/)/g,
      /window\.location\.assign\s*\(\s*(?!["'`]https?:\/\/)/g,
      /window\.location\.replace\s*\(\s*(?!["'`]https?:\/\/)/g,
      /res\.redirect\s*\(\s*(?:req\.|params\.|query\.)/gi,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, unvalidatedRedirect, filePath, () =>
        "Validate redirect URLs against an allowlist of trusted domains. Never redirect to user-supplied URLs directly."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC017 – Insecure cookie settings
// ────────────────────────────────────────────

const insecureCookies: CustomRule = {
  id: "VC017",
  title: "Insecure Cookie Settings",
  severity: "medium",
  category: "Configuration",
  description: "Cookies without httpOnly, secure, or sameSite flags are vulnerable to theft and CSRF attacks.",
  check(content, filePath) {
    if (!/cookie/i.test(content)) return [];
    const setCookiePattern = /(?:set-cookie|setCookie|cookie\s*=|res\.cookie\s*\()/gi;
    if (!setCookiePattern.test(content)) return [];
    const hasHttpOnly = /httpOnly\s*:\s*true|httponly/i.test(content);
    const hasSecure = /secure\s*:\s*true|;\s*secure/i.test(content);
    const hasSameSite = /sameSite\s*:|samesite/i.test(content);
    const matches: RuleMatch[] = [];
    if (!hasHttpOnly || !hasSecure || !hasSameSite) {
      const missing: string[] = [];
      if (!hasHttpOnly) missing.push("httpOnly");
      if (!hasSecure) missing.push("secure");
      if (!hasSameSite) missing.push("sameSite");
      matches.push(...findMatches(content, /(?:set-cookie|setCookie|cookie\s*=|res\.cookie\s*\()/gi, insecureCookies, filePath, () =>
        `Add missing cookie flags: ${missing.join(", ")}. Example: { httpOnly: true, secure: true, sameSite: 'lax' }`
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC018 – Exposed auth provider secret key
// ────────────────────────────────────────────

const exposedAuthSecret: CustomRule = {
  id: "VC018",
  title: "Exposed Clerk/Auth Secret Key",
  severity: "critical",
  category: "Secrets",
  description: "Auth provider secret keys (Clerk, Auth0, NextAuth) must never be in client-side code or NEXT_PUBLIC_ variables.",
  check(content, filePath) {
    const isClientFile = filePath.match(/\.(jsx|tsx|vue|svelte)$/) || /["']use client["']/.test(content);
    const isEnvFile = filePath.match(/\.env/);
    if (!isClientFile && !isEnvFile) return [];
    const patterns: RegExp[] = [];
    if (isClientFile) {
      patterns.push(
        /CLERK_SECRET_KEY/g,
        /AUTH0_CLIENT_SECRET/g,
        /NEXTAUTH_SECRET/g,
      );
    }
    if (isEnvFile) {
      patterns.push(
        /NEXT_PUBLIC_CLERK_SECRET/gi,
        /NEXT_PUBLIC_AUTH0_SECRET/gi,
        /NEXT_PUBLIC_NEXTAUTH_SECRET/gi,
      );
    }
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, exposedAuthSecret, filePath, () =>
        "Move this secret to a server-side environment variable (without the NEXT_PUBLIC_ prefix). Never expose auth secrets to the browser."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC019 – Insecure Electron BrowserWindow
// ────────────────────────────────────────────

const insecureElectronWindow: CustomRule = {
  id: "VC019",
  title: "Insecure Electron BrowserWindow Configuration",
  severity: "high",
  category: "Configuration",
  description: "Electron BrowserWindow with nodeIntegration enabled, contextIsolation disabled, or sandbox disabled allows renderer processes to access Node.js APIs, enabling remote code execution.",
  check(content, filePath) {
    if (!/BrowserWindow/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      /nodeIntegration\s*:\s*true/g,
      /contextIsolation\s*:\s*false/g,
      /sandbox\s*:\s*false/g,
      /webSecurity\s*:\s*false/g,
      /allowRunningInsecureContent\s*:\s*true/g,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, insecureElectronWindow, filePath, (m) =>
        `Set ${m[0].split(":")[0].trim()}: ${m[0].includes("true") ? "false" : "true"}. Enable contextIsolation, sandbox, and webSecurity; disable nodeIntegration and allowRunningInsecureContent.`
      ));
    }
    // Check for BrowserWindow without sandbox/webSecurity set at all
    if (/new\s+BrowserWindow\s*\(/g.test(content)) {
      if (!/sandbox\s*:/i.test(content)) {
        matches.push(...findMatches(content, /new\s+BrowserWindow\s*\(/g, { ...insecureElectronWindow, title: "Electron BrowserWindow Missing sandbox:true" }, filePath, () =>
          "Add sandbox: true to BrowserWindow webPreferences for defense in depth."
        ));
      }
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC020 – Missing Content Security Policy
// ────────────────────────────────────────────

const missingCSP: CustomRule = {
  id: "VC020",
  title: "Missing Content Security Policy (CSP)",
  severity: "high",
  category: "Configuration",
  description: "Without a Content-Security-Policy header or meta tag, your app is vulnerable to XSS and data injection attacks.",
  check(content, filePath) {
    // Check HTML files for missing CSP meta tag
    if (filePath.match(/\.(html|htm)$/)) {
      if (!/Content-Security-Policy/i.test(content)) {
        return [{
          rule: "VC020", title: missingCSP.title, severity: "high" as const, category: "Configuration",
          file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: 'Add a CSP meta tag: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'">'
        }];
      }
    }
    // Check Electron main process for missing CSP
    if (/BrowserWindow|electron/i.test(content) && /main|index/i.test(filePath)) {
      if (!/Content-Security-Policy/i.test(content) && !/helmet/i.test(content)) {
        if (/(?:loadFile|loadURL)/i.test(content)) {
          return findMatches(content, /(?:loadFile|loadURL)\s*\(/g, missingCSP, filePath, () =>
            "Set CSP headers in your Electron main process using session.defaultSession.webRequest.onHeadersReceived to restrict script and connect sources."
          );
        }
      }
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC021 – IPC Handler Without Path Validation
// ────────────────────────────────────────────

const ipcPathTraversal: CustomRule = {
  id: "VC021",
  title: "IPC/File Handler Without Path Validation",
  severity: "medium",
  category: "Injection",
  description: "IPC handlers that read or write files based on renderer-supplied paths without validation allow path traversal attacks, potentially exposing sensitive files like .ssh keys or .env files.",
  check(content, filePath) {
    if (!/ipcMain\.handle|ipcMain\.on/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    // Look for file read/write in IPC handlers without path validation
    const hasFileOps = /readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream/i.test(content);
    if (!hasFileOps) return [];
    const hasPathValidation = /(?:path\.resolve|path\.normalize|startsWith|isAbsolute|\.includes\s*\(\s*["'`]\.\.["'`]\s*\)|allowedPaths|safePath|validatePath|sanitizePath)/i.test(content);
    if (!hasPathValidation) {
      matches.push(...findMatches(content, /ipcMain\.(?:handle|on)\s*\(\s*["'`][^"'`]*(?:read|write|file|save|load|open|export)[^"'`]*["'`]/gi, ipcPathTraversal, filePath, () =>
        "Validate file paths in IPC handlers: ensure paths are within an allowed directory (e.g., app.getPath('userData')), reject paths containing '..', and block access to sensitive directories (.ssh, .env, etc)."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC022 – HTML Export Without Sanitization
// ────────────────────────────────────────────

const unsanitizedHTMLExport: CustomRule = {
  id: "VC022",
  title: "HTML Export/Render Without Sanitization",
  severity: "critical",
  category: "Injection",
  description: "Generating HTML from user content without sanitization (e.g., DOMPurify) allows stored XSS attacks. Malicious content saved in documents could execute scripts when exported or previewed.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    // Template literals building HTML with user variables
    const htmlBuildPatterns = [
      /`<[^`]*\$\{[^}]*(?:content|title|body|text|name|message|description|input|value|data)[^}]*\}[^`]*>`/gi,
      /["']<[^"']*['"]\s*\+\s*(?:content|title|body|text|message|data|doc\.|post\.|article\.)/gi,
    ];
    const hasSanitizer = /DOMPurify|sanitize|escapeHtml|escape|xss|encode|htmlEncode/i.test(content);
    if (hasSanitizer) return [];
    for (const p of htmlBuildPatterns) {
      matches.push(...findMatches(content, p, unsanitizedHTMLExport, filePath, () =>
        "Sanitize user content before embedding in HTML. Use DOMPurify: DOMPurify.sanitize(content). For plain text, use a function to escape HTML entities (<, >, &, quotes)."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC023 – Prototype Pollution via Storage
// ────────────────────────────────────────────

const prototypePollution: CustomRule = {
  id: "VC023",
  title: "Prototype Pollution Risk",
  severity: "high",
  category: "Injection",
  description: "Parsing JSON from localStorage, URL params, or external sources and merging it into objects without validation can lead to prototype pollution, allowing attackers to inject __proto__ or constructor properties.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    // JSON.parse from localStorage/sessionStorage without validation
    const storageParsePatterns = [
      /JSON\.parse\s*\(\s*(?:localStorage|sessionStorage)\.getItem/g,
      /JSON\.parse\s*\(\s*window\.localStorage/g,
    ];
    const hasValidation = /schema|validate|sanitize|whitelist|allowedKeys|pick\(|Object\.freeze|zod|yup|joi|ajv/i.test(content);
    if (hasValidation) return [];
    // Check for object spread/assign from parsed storage
    const hasUnsafeMerge = /Object\.assign\s*\([^)]*JSON\.parse|\.\.\.JSON\.parse|\{.*\.\.\.(?:stored|saved|cached|parsed|data)/i.test(content);
    if (hasUnsafeMerge) {
      matches.push(...findMatches(content, /Object\.assign\s*\([^)]*JSON\.parse|\.\.\.JSON\.parse/g, prototypePollution, filePath, () =>
        "Validate parsed data against an expected schema before merging into objects. Use Object.freeze(), a validation library (Zod, Yup), or manually check for __proto__ and constructor keys."
      ));
    }
    for (const p of storageParsePatterns) {
      matches.push(...findMatches(content, p, prototypePollution, filePath, () =>
        "Validate localStorage data against an expected schema before using it. Malicious extensions or XSS can modify localStorage values."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC024 – Missing File Size Limits
// ────────────────────────────────────────────

const missingFileSizeLimits: CustomRule = {
  id: "VC024",
  title: "File Write/Save Without Size Limit",
  severity: "medium",
  category: "Availability",
  description: "File save or upload handlers without size validation can lead to denial-of-service via disk exhaustion or memory exhaustion.",
  check(content, filePath) {
    if (!/(?:writeFile|save|upload|export)/i.test(filePath) && !/(?:writeFile|writeFileSync|createWriteStream)/i.test(content)) return [];
    // Look for file write operations in handlers
    const hasWriteOps = /(?:ipcMain|app\.(?:post|put)|router\.(?:post|put)).*(?:writeFile|save|export)/is.test(content) ||
                        /(?:writeFile|writeFileSync)\s*\(/g.test(content);
    if (!hasWriteOps) return [];
    const hasSizeCheck = /(?:size|length|byteLength|bytes)\s*(?:>|>=|<|<=|===)\s*\d|maxSize|MAX_SIZE|sizeLimit|content-length/i.test(content);
    if (hasSizeCheck) return [];
    return findMatches(content, /(?:writeFile|writeFileSync)\s*\(/g, missingFileSizeLimits, filePath, () =>
      "Add file size validation before writing. Check content.length or Buffer.byteLength() against a maximum (e.g., 10MB) to prevent disk exhaustion."
    );
  },
};

// ────────────────────────────────────────────
// VC025 – Unsanitized Export Filenames
// ────────────────────────────────────────────

const unsanitizedFilenames: CustomRule = {
  id: "VC025",
  title: "Unsanitized Filename in File Operations",
  severity: "medium",
  category: "Injection",
  description: "Using user-supplied filenames without sanitization in file operations can enable path traversal, overwriting system files, or executing commands via special characters.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    // Look for file operations using variables as filenames
    const patterns = [
      /(?:writeFile|writeFileSync|createWriteStream|rename|copyFile)\s*\(\s*(?:`[^`]*\$\{|[^"'`\s,]+\s*\+)/g,
      /(?:dialog\.showSaveDialog|saveDialog).*(?:defaultPath|fileName)\s*:\s*(?!["'`])/g,
      /\.download\s*=\s*(?!["'`])/g,
    ];
    const hasSanitization = /sanitize|cleanFilename|safeFilename|replace\s*\(\s*\/\[.*\]\//i.test(content);
    if (hasSanitization) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, unsanitizedFilenames, filePath, () =>
        "Sanitize filenames before use: strip path separators (/ \\), special chars, and '..' sequences. Example: name.replace(/[^a-zA-Z0-9._-]/g, '_')"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC026 – Electron Navigation Not Restricted
// ────────────────────────────────────────────

const electronNavigationUnrestricted: CustomRule = {
  id: "VC026",
  title: "Electron: External Navigation Not Blocked",
  severity: "medium",
  category: "Configuration",
  description: "Electron apps that don't block navigation to external URLs or new window creation are vulnerable to phishing and drive-by downloads. Malicious links in app content can redirect the entire app to an attacker's site.",
  check(content, filePath) {
    if (!/BrowserWindow|electron/i.test(content)) return [];
    if (!/main|index/i.test(filePath)) return [];
    const hasNavBlock = /will-navigate|new-window|setWindowOpenHandler|webContents\.on.*navigate/i.test(content);
    if (hasNavBlock) return [];
    if (/new\s+BrowserWindow/i.test(content)) {
      return findMatches(content, /new\s+BrowserWindow\s*\(/g, electronNavigationUnrestricted, filePath, () =>
        "Block external navigation: win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file://')) e.preventDefault(); }); and use setWindowOpenHandler to block new windows."
      );
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC027 – Missing Security Meta Tags
// ────────────────────────────────────────────

const missingSecurityMeta: CustomRule = {
  id: "VC027",
  title: "Missing Security Meta Tags / Headers",
  severity: "medium",
  category: "Configuration",
  description: "HTML pages without X-Content-Type-Options, referrer policy, or other security meta tags are more susceptible to MIME-sniffing attacks and information leakage.",
  check(content, filePath) {
    if (!filePath.match(/\.(html|htm)$/)) return [];
    const matches: RuleMatch[] = [];
    if (!/X-Content-Type-Options/i.test(content) && !/<meta[^>]*nosniff/i.test(content)) {
      matches.push({
        rule: "VC027", title: "Missing X-Content-Type-Options Header", severity: "medium" as const,
        category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
        fix: 'Add <meta http-equiv="X-Content-Type-Options" content="nosniff"> to prevent MIME-type sniffing.'
      });
    }
    if (!/referrer/i.test(content)) {
      matches.push({
        rule: "VC027", title: "Missing Referrer Policy", severity: "medium" as const,
        category: "Configuration", file: filePath, line: 1, snippet: getSnippet(content, 1),
        fix: 'Add <meta name="referrer" content="no-referrer"> or "strict-origin-when-cross-origin" to limit referrer leakage.'
      });
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC028 – Unvalidated API Parameters
// ────────────────────────────────────────────

const unvalidatedAPIParams: CustomRule = {
  id: "VC028",
  title: "Unvalidated API Request Parameters",
  severity: "high",
  category: "Injection",
  description: "API requests constructed with unvalidated user input (API keys, model names, URLs) can be exploited for injection attacks or unauthorized access to different API models/endpoints.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    // API key passed without format validation
    const apiKeyPatterns = [
      /(?:apiKey|api_key|authorization)\s*[:=]\s*(?:req\.body|req\.query|params|input|formData|body)\./gi,
      /headers\s*:\s*\{[^}]*Authorization\s*:\s*(?!["'`]Bearer\s)/gi,
    ];
    const hasValidation = /validate|sanitize|regex|test\(|match\(|pattern|allowList|whitelist|enum|includes\(/i.test(content);
    if (hasValidation) return [];
    // Model selection without allowlist
    if (/model\s*[:=]\s*(?:req\.body|params|input|body)\./i.test(content) || /model\s*[:=]\s*(?!["'`])[a-z]/i.test(content)) {
      const hasModelValidation = /allowedModels|validModels|models\s*\.\s*includes|model.*(?:===|!==|includes)/i.test(content);
      if (!hasModelValidation && /(?:openai|anthropic|claude|gpt|llm)/i.test(content)) {
        matches.push(...findMatches(content, /model\s*[:=]\s*(?:req\.body|params|input|body)\./gi, unvalidatedAPIParams, filePath, () =>
          "Validate model selection against an allowlist of approved models. Example: const ALLOWED_MODELS = ['gpt-4', 'claude-3']; if (!ALLOWED_MODELS.includes(model)) throw new Error('Invalid model');"
        ));
      }
    }
    for (const p of apiKeyPatterns) {
      matches.push(...findMatches(content, p, unvalidatedAPIParams, filePath, () =>
        "Validate API key format before using it (e.g., check prefix and length). Never pass user-supplied API keys directly to third-party services without validation."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC029 – Unvalidated Event/Message Data
// ────────────────────────────────────────────

const unvalidatedEventData: CustomRule = {
  id: "VC029",
  title: "Unvalidated Event or PostMessage Data",
  severity: "medium",
  category: "Injection",
  description: "Custom events, postMessage, or IPC message data used without type-checking can lead to injection attacks or unexpected behavior when malicious data is sent through event channels.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    // addEventListener('message') without origin check
    if (/addEventListener\s*\(\s*["'`]message["'`]/i.test(content)) {
      if (!/event\.origin|e\.origin|message\.origin/i.test(content)) {
        matches.push(...findMatches(content, /addEventListener\s*\(\s*["'`]message["'`]/g, unvalidatedEventData, filePath, () =>
          "Always verify event.origin in message event handlers to prevent cross-origin attacks. Example: if (event.origin !== 'https://trusted.com') return;"
        ));
      }
    }
    // dispatchEvent with custom data inserted without validation
    if (/new\s+CustomEvent\s*\(/i.test(content) || /ipcRenderer\.send/i.test(content)) {
      const hasTypeCheck = /typeof\s|instanceof|z\.|schema|validate|Number\.isFinite|parseInt|parseFloat/i.test(content);
      if (!hasTypeCheck) {
        matches.push(...findMatches(content, /new\s+CustomEvent\s*\(/g, unvalidatedEventData, filePath, () =>
          "Type-check custom event data before using it. Validate that data.detail contains expected types to prevent injection."
        ));
      }
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// EXPORT ALL RULES
// ────────────────────────────────────────────

export const allRules: CustomRule[] = [
  hardcodedSecrets,
  exposedEnvFile,
  missingAuthMiddleware,
  supabaseNoRLS,
  stripeWebhookUnprotected,
  sqlInjection,
  xssVulnerability,
  noRateLimiting,
  corsWildcard,
  clientSideAuth,
  nextPublicSecret,
  firebaseClientConfig,
  supabaseAnonAdmin,
  envNotGitignored,
  evalUsage,
  unvalidatedRedirect,
  insecureCookies,
  exposedAuthSecret,
  insecureElectronWindow,
  missingCSP,
  ipcPathTraversal,
  unsanitizedHTMLExport,
  prototypePollution,
  missingFileSizeLimits,
  unsanitizedFilenames,
  electronNavigationUnrestricted,
  missingSecurityMeta,
  unvalidatedAPIParams,
  unvalidatedEventData,
];

export function runCustomRules(
  content: string,
  filePath: string,
  disabledRules: string[] = [],
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of allRules) {
    if (disabledRules.includes(rule.id)) continue;

    const matches = rule.check(content, filePath);
    for (const match of matches) {
      findings.push({
        id: `${match.rule}-${match.file}:${match.line}`,
        rule: match.rule,
        severity: match.severity,
        title: match.title,
        description: rule.description,
        file: match.file,
        line: match.line,
        column: match.column,
        snippet: match.snippet,
        fix: match.fix,
        category: match.category,
        source: "custom",
      });
    }
  }

  return findings;
}
