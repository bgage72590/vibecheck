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
// VC030 – Insecure Deserialization
// ────────────────────────────────────────────

const insecureDeserialization: CustomRule = {
  id: "VC030",
  title: "Insecure Deserialization",
  severity: "critical",
  category: "Injection",
  description: "Deserializing untrusted data (pickle, unserialize, yaml.load) can execute arbitrary code. Attackers craft malicious payloads to gain remote code execution.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    const patterns = [
      // Python pickle
      /pickle\.loads?\s*\(/g,
      /cPickle\.loads?\s*\(/g,
      // PHP unserialize
      /unserialize\s*\(/g,
      // Ruby Marshal
      /Marshal\.load\s*\(/g,
      // YAML unsafe load (Python)
      /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
      /yaml\.unsafe_load\s*\(/g,
      // Java ObjectInputStream
      /ObjectInputStream\s*\(/g,
      // Node.js node-serialize
      /serialize\.unserialize\s*\(/g,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, insecureDeserialization, filePath, () =>
        "Never deserialize untrusted data. Use JSON instead of pickle/Marshal/unserialize. For YAML, use yaml.safe_load(). Validate and sanitize all input before deserialization."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC031 – Hardcoded JWT Secret
// ────────────────────────────────────────────

const hardcodedJWTSecret: CustomRule = {
  id: "VC031",
  title: "Hardcoded JWT Secret",
  severity: "critical",
  category: "Secrets",
  description: "JWT tokens signed with a hardcoded string secret can be forged by anyone who reads the source code.",
  check(content, filePath) {
    if (filePath.endsWith(".example") || filePath.endsWith(".template") || filePath.includes("test")) return [];
    const patterns = [
      /jwt\.sign\s*\([^,]+,\s*["'`][^"'`]{3,}["'`]/g,
      /jwt\.verify\s*\([^,]+,\s*["'`][^"'`]{3,}["'`]/g,
      /jsonwebtoken.*secret\s*[:=]\s*["'`][^"'`]{3,}["'`]/gi,
      /JWT_SECRET\s*[:=]\s*["'`][^"'`]{3,}["'`]/g,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, hardcodedJWTSecret, filePath, () =>
        "Move JWT secret to an environment variable: jwt.sign(payload, process.env.JWT_SECRET). Use a strong, random secret (256+ bits)."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC032 – Missing HTTPS Enforcement
// ────────────────────────────────────────────

const missingHTTPS: CustomRule = {
  id: "VC032",
  title: "Missing HTTPS Enforcement",
  severity: "high",
  category: "Configuration",
  description: "HTTP URLs in production code, missing HSTS headers, or insecure redirect configurations expose data to man-in-the-middle attacks.",
  check(content, filePath) {
    if (filePath.endsWith(".example") || filePath.includes("test") || filePath.includes("README")) return [];
    if (filePath.match(/\.(md|txt)$/)) return [];
    const matches: RuleMatch[] = [];
    // Hardcoded http:// URLs to non-local hosts
    const httpPattern = /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)[^"'`\s]+["'`]/g;
    matches.push(...findMatches(content, httpPattern, missingHTTPS, filePath, () =>
      "Use https:// instead of http:// for all production URLs. Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ));
    return matches;
  },
};

// ────────────────────────────────────────────
// VC033 – Exposed Debug/Dev Mode
// ────────────────────────────────────────────

const exposedDebugMode: CustomRule = {
  id: "VC033",
  title: "Debug/Development Mode Exposed",
  severity: "high",
  category: "Configuration",
  description: "Debug mode, verbose logging, or development configuration left in production code exposes internal details and may enable debug endpoints.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.endsWith(".example") || filePath.includes("node_modules")) return [];
    if (filePath.match(/\.env\.development$/)) return []; // Expected in dev env files
    const matches: RuleMatch[] = [];
    const patterns = [
      // Debug flags set to true
      /DEBUG\s*[:=]\s*(?:true|1|["'`]true["'`]|["'`]\*["'`])/g,
      // Django DEBUG
      /DEBUG\s*=\s*True/g,
      // Flask/Express debug mode
      /app\.debug\s*=\s*True/g,
      /app\.run\s*\([^)]*debug\s*=\s*True/g,
      // Source maps in production
      /devtool\s*:\s*["'`](?:eval|cheap|source-map|inline-source-map)["'`]/g,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, exposedDebugMode, filePath, () =>
        "Disable debug mode in production. Use environment variables: DEBUG = process.env.NODE_ENV !== 'production'. Remove source maps from production builds."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC034 – Insecure Randomness
// ────────────────────────────────────────────

const insecureRandomness: CustomRule = {
  id: "VC034",
  title: "Insecure Randomness for Security-Sensitive Values",
  severity: "high",
  category: "Cryptography",
  description: "Math.random() is not cryptographically secure. Using it for tokens, session IDs, passwords, or OTPs makes them predictable.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock") || filePath.includes("seed")) return [];
    const matches: RuleMatch[] = [];
    // Math.random used near security-related terms
    const securityContext = /(?:token|secret|session|password|otp|nonce|salt|key|csrf|auth|verify|code)\s*[:=].*Math\.random/gi;
    matches.push(...findMatches(content, securityContext, insecureRandomness, filePath, () =>
      "Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive values. Math.random() is predictable."
    ));
    // Math.random used to generate IDs
    const idContext = /(?:id|uuid|guid|identifier)\s*[:=].*Math\.random/gi;
    matches.push(...findMatches(content, idContext, insecureRandomness, filePath, () =>
      "Use crypto.randomUUID() for generating unique IDs. Math.random() can produce collisions and is predictable."
    ));
    return matches;
  },
};

// ────────────────────────────────────────────
// VC035 – Open Redirect via URL Params
// ────────────────────────────────────────────

const openRedirectParams: CustomRule = {
  id: "VC035",
  title: "Open Redirect via URL Parameters",
  severity: "high",
  category: "Injection",
  description: "Redirect parameters like ?redirect_url=, ?return_to=, ?next= passed directly to redirects enable phishing attacks.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    const patterns = [
      // Reading redirect-like query params and using in redirect
      /(?:redirect_url|redirect_uri|return_to|return_url|next|callback_url|continue|goto|target|dest|destination|forward|redir)\s*(?:=|:)\s*(?:req\.query|req\.params|searchParams|query|params)\./gi,
      /redirect\s*\(\s*(?:req\.query|req\.params|searchParams\.get)\s*\(\s*["'`](?:redirect|return|next|callback|url|goto)/gi,
    ];
    const hasValidation = /allowedUrls|allowedDomains|allowedHosts|validUrl|safeDomain|whitelist|startsWith.*https|new URL.*hostname/i.test(content);
    if (hasValidation) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, openRedirectParams, filePath, () =>
        "Validate redirect URLs against an allowlist of trusted domains. Use: const url = new URL(input); if (!ALLOWED_HOSTS.includes(url.hostname)) reject."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC036 – Missing Error Boundary (React)
// ────────────────────────────────────────────

const missingErrorBoundary: CustomRule = {
  id: "VC036",
  title: "React App Missing Error Boundary",
  severity: "medium",
  category: "Configuration",
  description: "React apps without error boundaries display raw stack traces and component tree info to users when crashes occur, leaking internal details.",
  check(content, filePath) {
    // Only check top-level layout/app files
    if (!filePath.match(/(?:layout|_app|App|main)\.[jt]sx?$/)) return [];
    if (!/(?:React|react|jsx|tsx)/i.test(content)) return [];
    const hasErrorBoundary = /ErrorBoundary|componentDidCatch|getDerivedStateFromError|error-boundary/i.test(content);
    if (hasErrorBoundary) return [];
    // Check if it renders child components
    if (/children|<[A-Z]|Component|Outlet/i.test(content)) {
      return [{
        rule: "VC036", title: missingErrorBoundary.title, severity: "medium" as const, category: "Configuration",
        file: filePath, line: 1, snippet: getSnippet(content, 1),
        fix: "Wrap your app in an ErrorBoundary component to catch rendering errors gracefully. Use react-error-boundary or create a class component with componentDidCatch."
      }];
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC037 – Exposed Stack Traces in API
// ────────────────────────────────────────────

const exposedStackTraces: CustomRule = {
  id: "VC037",
  title: "Stack Traces Exposed in API Responses",
  severity: "medium",
  category: "Information Leakage",
  description: "Returning error.stack or detailed error messages in API responses reveals internal code paths, file structure, and dependencies to attackers.",
  check(content, filePath) {
    const isApiFile = /(?:\/api\/|routes?\/|controllers?\/|server\.|middleware)/i.test(filePath);
    if (!isApiFile) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      // Sending stack trace in response
      /(?:res\.(?:json|send|status)|c\.json|return.*json)\s*\([^)]*(?:err\.stack|error\.stack|e\.stack)/gi,
      /(?:res\.(?:json|send|status)|c\.json)\s*\([^)]*(?:err\.message|error\.message|e\.message)/gi,
      // Express-style error with stack
      /(?:message|error)\s*:\s*(?:err|error|e)\.(?:stack|message)/gi,
    ];
    const hasEnvCheck = /process\.env\.NODE_ENV\s*(?:===|!==)\s*["'`]production["'`]|NODE_ENV/i.test(content);
    if (hasEnvCheck) return []; // They're conditionally showing errors
    for (const p of patterns) {
      matches.push(...findMatches(content, p, exposedStackTraces, filePath, () =>
        "Never expose error.stack or error.message to clients in production. Return generic error messages: { error: 'Something went wrong' }. Log details server-side only."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC038 – Insecure File Upload Type
// ────────────────────────────────────────────

const insecureFileUpload: CustomRule = {
  id: "VC038",
  title: "Insecure File Upload Validation",
  severity: "high",
  category: "Injection",
  description: "File uploads validated only by extension (not MIME type or content) allow attackers to upload executable files disguised as images or documents.",
  check(content, filePath) {
    if (!/upload|multer|formidable|busboy|multipart/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    // Check for extension-only validation
    const hasExtCheck = /\.(?:endsWith|match|test)\s*\([^)]*(?:\.jpg|\.png|\.pdf|\.doc|ext)/i.test(content);
    const hasMimeCheck = /mimetype|content-type|file\.type|mime|magic\.detect|file-type/i.test(content);
    if (hasExtCheck && !hasMimeCheck) {
      matches.push(...findMatches(content, /upload|multer|formidable|busboy/gi, insecureFileUpload, filePath, () =>
        "Validate file uploads by MIME type AND magic bytes, not just extension. Use the 'file-type' package to detect actual file type from content. Also enforce size limits."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC039 – Missing Dependency Lock File
// ────────────────────────────────────────────

const missingLockFile: CustomRule = {
  id: "VC039",
  title: "Missing Dependency Lock File",
  severity: "medium",
  category: "Supply Chain",
  description: "Without a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock), dependency versions are unpinned and vulnerable to supply chain attacks via version substitution.",
  check(content, filePath) {
    // Only check .gitignore for lock files being ignored
    if (!filePath.endsWith(".gitignore")) return [];
    const ignoresLock = /package-lock\.json|pnpm-lock\.yaml|yarn\.lock/i.test(content);
    if (ignoresLock) {
      return findMatches(content, /(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock)/gi, missingLockFile, filePath, () =>
        "Remove the lockfile from .gitignore. Lockfiles should be committed to prevent supply chain attacks. They ensure exact versions are installed across all environments."
      );
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC040 – Exposed .git Directory
// ────────────────────────────────────────────

const exposedGitDir: CustomRule = {
  id: "VC040",
  title: "Exposed .git Directory via Web Server",
  severity: "critical",
  category: "Information Leakage",
  description: "Web server configs that don't block access to .git directories expose your entire source code, commit history, secrets, and credentials.",
  check(content, filePath) {
    // Check web server configs
    if (!filePath.match(/(?:nginx|apache|httpd|caddy|\.htaccess|vercel\.json|netlify\.toml|server\.[jt]s)/i)) return [];
    // For static file servers, check they block .git
    if (/(?:static|serve|express\.static|serveStatic|public)/i.test(content)) {
      const blocksGit = /\.git|dotfiles|hidden/i.test(content);
      if (!blocksGit) {
        return findMatches(content, /(?:static|serve|express\.static|serveStatic)\s*\(/g, exposedGitDir, filePath, () =>
          "Block access to .git and other dotfiles in your static file server config. For Express: app.use('/.git', (req, res) => res.status(403).end()). For Nginx: location ~ /\\.git { deny all; }"
        );
      }
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC041 – Server-Side Request Forgery (SSRF)
// ────────────────────────────────────────────

const ssrfVulnerability: CustomRule = {
  id: "VC041",
  title: "Potential Server-Side Request Forgery (SSRF)",
  severity: "critical",
  category: "Injection",
  description: "Fetching URLs from user input without validation allows attackers to access internal services, cloud metadata endpoints (169.254.169.254), and private networks.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock")) return [];
    const matches: RuleMatch[] = [];
    // fetch/axios/http with user-controlled URLs
    const patterns = [
      /(?:fetch|axios\.get|axios\.post|axios|got|request|http\.get|https\.get)\s*\(\s*(?:req\.(?:body|query|params)|body|input|params|args)\./gi,
      /(?:fetch|axios\.get|axios\.post|got|request)\s*\(\s*(?!["'`]https?:\/\/)[a-zA-Z_$][\w$]*\s*[,)]/g,
    ];
    const hasValidation = /allowedHosts|allowedDomains|allowedUrls|safeDomain|whitelist|urlValidator|new URL.*hostname.*includes|isAllowedUrl/i.test(content);
    if (hasValidation) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, ssrfVulnerability, filePath, () =>
        "Validate URLs against an allowlist before fetching. Block internal IPs: 127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.169.254 (cloud metadata). Use: const url = new URL(input); if (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error('Blocked');"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC042 – Mass Assignment
// ────────────────────────────────────────────

const massAssignment: CustomRule = {
  id: "VC042",
  title: "Mass Assignment Vulnerability",
  severity: "high",
  category: "Authorization",
  description: "Spreading or assigning request body directly into database models allows attackers to set fields they shouldn't (e.g., isAdmin, role, verified).",
  check(content, filePath) {
    const isApiFile = /(?:\/api\/|routes?\/|controllers?\/|server\.|handler)/i.test(filePath);
    if (!isApiFile) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      // Object.assign(model, req.body)
      /Object\.assign\s*\(\s*(?:user|account|profile|record|doc|model|entity)[^,]*,\s*(?:req\.body|body|input|data)\s*\)/gi,
      // Spread req.body into create/update
      /(?:create|update|insert|save|findOneAndUpdate|updateOne|upsert)\s*\(\s*\{[^}]*\.\.\.(?:req\.body|body|input|data)/gi,
      // Direct req.body into DB
      /(?:create|insert|save)\s*\(\s*(?:req\.body|body)\s*\)/gi,
    ];
    const hasSanitization = /pick\(|omit\(|allowedFields|sanitize|whitelist|permit|strong_params/i.test(content);
    if (hasSanitization) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, massAssignment, filePath, () =>
        "Never pass req.body directly to database operations. Explicitly pick allowed fields: const { name, email } = req.body; await db.create({ name, email });"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC043 – Timing Attack on Comparison
// ────────────────────────────────────────────

const timingAttack: CustomRule = {
  id: "VC043",
  title: "Timing-Unsafe Secret Comparison",
  severity: "medium",
  category: "Cryptography",
  description: "Using === to compare secrets, tokens, or hashes leaks information via timing side-channels. Attackers can determine the correct value one character at a time.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock")) return [];
    const matches: RuleMatch[] = [];
    // Direct comparison of secrets/tokens/hashes
    const patterns = [
      /(?:token|secret|hash|digest|signature|hmac|apiKey|api_key)\s*(?:===|!==)\s*(?:req\.|body\.|params\.|query\.|input)/gi,
      /(?:req\.|body\.|params\.|query\.|input)[\w.]*(?:token|secret|hash|digest|signature|hmac)\s*(?:===|!==)/gi,
    ];
    const hasTimingSafe = /timingSafeEqual|constantTimeEqual|safeCompare|secureCompare/i.test(content);
    if (hasTimingSafe) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, timingAttack, filePath, () =>
        "Use crypto.timingSafeEqual() for comparing secrets: crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)). This prevents timing-based side-channel attacks."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC044 – Log Injection
// ────────────────────────────────────────────

const logInjection: CustomRule = {
  id: "VC044",
  title: "Potential Log Injection",
  severity: "medium",
  category: "Injection",
  description: "Logging unsanitized user input allows attackers to forge log entries, inject malicious content, or exploit log aggregation systems via newlines and special characters.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock")) return [];
    const isServerFile = /(?:\/api\/|routes?\/|controllers?\/|server\.|middleware|handler)/i.test(filePath);
    if (!isServerFile) return [];
    const matches: RuleMatch[] = [];
    // console.log/warn/error with req.body/query/params directly
    const patterns = [
      /console\.(?:log|warn|error|info)\s*\([^)]*(?:req\.body|req\.query|req\.params|req\.headers)\s*\)/gi,
      /(?:logger|log)\.(?:info|warn|error|debug)\s*\([^)]*(?:req\.body|req\.query|req\.params)\s*\)/gi,
    ];
    const hasSanitization = /sanitize|escape|JSON\.stringify|replace.*\\n/i.test(content);
    if (hasSanitization) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, logInjection, filePath, () =>
        "Sanitize user input before logging: strip newlines and control characters. Use JSON.stringify() or a structured logger (e.g., pino, winston) that escapes values automatically."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC045 – Weak Password Requirements
// ────────────────────────────────────────────

const weakPasswordRequirements: CustomRule = {
  id: "VC045",
  title: "Weak Password Requirements",
  severity: "high",
  category: "Authentication",
  description: "Registration or password-change endpoints without minimum length or complexity validation allow weak passwords that are easily brute-forced.",
  check(content, filePath) {
    if (!/(?:password|passwd|pwd)/i.test(content)) return [];
    if (!/(?:register|signup|sign.up|createUser|create.user|changePassword|resetPassword|set.password)/i.test(content) &&
        !/(?:\/api\/|routes?\/|controllers?\/)/i.test(filePath)) return [];
    const hasValidation = /(?:password|pwd).*(?:\.length|minLength|minlength|min_length)\s*(?:>=?|<|>)\s*\d|(?:password|pwd).*(?:match|test|regex|pattern)|zxcvbn|password-validator|passwordStrength|isStrongPassword/i.test(content);
    if (hasValidation) return [];
    const hasPasswordHandling = /(?:password|pwd)\s*[:=]\s*(?:req\.body|body|input|params|args)\./i.test(content);
    if (!hasPasswordHandling) return [];
    return findMatches(content, /(?:password|pwd)\s*[:=]\s*(?:req\.body|body|input|params|args)\./gi, weakPasswordRequirements, filePath, () =>
      "Enforce minimum password requirements: at least 8 characters, mix of letters/numbers/symbols. Use a library like zxcvbn for strength estimation."
    );
  },
};

// ────────────────────────────────────────────
// VC046 – Session Fixation
// ────────────────────────────────────────────

const sessionFixation: CustomRule = {
  id: "VC046",
  title: "Session Fixation Risk",
  severity: "high",
  category: "Authentication",
  description: "Not regenerating session IDs after login allows attackers to pre-set a session ID and hijack the authenticated session.",
  check(content, filePath) {
    if (!/(?:login|signin|sign.in|authenticate)/i.test(content)) return [];
    if (!/session/i.test(content)) return [];
    const hasRegenerate = /regenerate|destroy.*create|req\.session\.id\s*=|session\.regenerateId|rotateSession/i.test(content);
    if (hasRegenerate) return [];
    const hasLogin = /(?:login|signin|authenticate)\s*(?:=|:|\()/i.test(content);
    if (!hasLogin) return [];
    return findMatches(content, /(?:login|signin|authenticate)\s*(?:=|:|\()/gi, sessionFixation, filePath, () =>
      "Regenerate the session ID after successful login: req.session.regenerate() (Express) or equivalent. This prevents session fixation attacks."
    );
  },
};

// ────────────────────────────────────────────
// VC047 – Missing Brute Force Protection
// ────────────────────────────────────────────

const missingBruteForce: CustomRule = {
  id: "VC047",
  title: "Login Without Brute Force Protection",
  severity: "high",
  category: "Authentication",
  description: "Login endpoints without rate limiting, account lockout, or progressive delays are vulnerable to credential stuffing and brute force attacks.",
  check(content, filePath) {
    const isLoginFile = /(?:login|signin|sign.in|auth)/i.test(filePath) || /(?:login|signin|authenticate).*(?:post|handler|route)/i.test(content);
    if (!isLoginFile) return [];
    if (!/(?:password|credential)/i.test(content)) return [];
    const hasBruteForce = /rate.?limit|throttle|lockout|maxAttempts|max_attempts|failedAttempts|loginAttempts|brute|express-brute|express-rate-limit|slowDown/i.test(content);
    if (hasBruteForce) return [];
    return findMatches(content, /\.(post|handler)\s*\([^)]*(?:login|signin|auth)/gi, missingBruteForce, filePath, () =>
      "Add brute force protection to login endpoints: rate limiting (5 attempts/minute), progressive delays, or account lockout after N failures. Use express-rate-limit or similar."
    );
  },
};

// ────────────────────────────────────────────
// VC048 – NoSQL Injection
// ────────────────────────────────────────────

const nosqlInjection: CustomRule = {
  id: "VC048",
  title: "Potential NoSQL Injection",
  severity: "critical",
  category: "Injection",
  description: "Passing unsanitized user input directly into MongoDB/NoSQL queries allows attackers to bypass authentication, extract data, or modify queries using operators like $gt, $ne, $regex.",
  check(content, filePath) {
    if (!/(?:mongo|mongoose|findOne|findById|find\(|collection|aggregate)/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      // Direct req.body in MongoDB queries
      /\.find(?:One)?\s*\(\s*(?:req\.body|body|input|params)\s*\)/gi,
      /\.find(?:One)?\s*\(\s*\{[^}]*:\s*(?:req\.body|body|input|params)\./gi,
      // $where with user input
      /\$where\s*:\s*(?!["'`])/g,
      // Direct variable in query without sanitization
      /\.(?:findOne|findById|deleteOne|updateOne|findOneAndUpdate)\s*\(\s*\{[^}]*:\s*(?:req\.(?:body|query|params))\./gi,
    ];
    const hasSanitization = /sanitize|escape|mongo-sanitize|express-mongo-sanitize|validator|typeof.*===.*string/i.test(content);
    if (hasSanitization) return [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, nosqlInjection, filePath, () =>
        "Sanitize MongoDB query inputs: use express-mongo-sanitize, validate types (ensure strings aren't objects), and avoid $where. Example: if (typeof input !== 'string') throw new Error('Invalid input');"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC049 – Exposed DB Credentials in Config
// ────────────────────────────────────────────

const exposedDBCredentials: CustomRule = {
  id: "VC049",
  title: "Database Credentials in Config File",
  severity: "critical",
  category: "Secrets",
  description: "Database connection strings with embedded usernames and passwords in committed config files expose credentials to anyone with repo access.",
  check(content, filePath) {
    if (filePath.endsWith(".example") || filePath.endsWith(".template")) return [];
    if (!filePath.match(/(?:config|setting|database|db|knexfile|sequelize|drizzle|prisma)/i) && !filePath.match(/\.(json|yaml|yml|toml|js|ts)$/)) return [];
    if (filePath.match(/\.env/)) return []; // Handled by VC002
    const patterns = [
      // Connection strings with credentials
      /(?:host|server|database|db).*(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{3,}["'`]/gi,
      // Inline connection URLs with credentials
      /(?:connection|database|db).*(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/gi,
    ];
    const matches: RuleMatch[] = [];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, exposedDBCredentials, filePath, () =>
        "Move database credentials to environment variables. Use: process.env.DATABASE_URL instead of hardcoding connection strings in config files."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC050 – Missing DB Connection Encryption
// ────────────────────────────────────────────

const missingDBEncryption: CustomRule = {
  id: "VC050",
  title: "Database Connection Without SSL/TLS",
  severity: "high",
  category: "Configuration",
  description: "Database connections without SSL/TLS encryption transmit credentials and data in plaintext, allowing eavesdropping on the network.",
  check(content, filePath) {
    if (!/(?:createConnection|createPool|createClient|connect|new.*Client|knex|sequelize|drizzle)/i.test(content)) return [];
    if (!/(?:postgres|mysql|mariadb|pg|mongo)/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    // SSL explicitly disabled
    const sslDisabled = [
      /ssl\s*:\s*false/gi,
      /sslmode\s*[:=]\s*["'`]?disable["'`]?/gi,
      /rejectUnauthorized\s*:\s*false/gi,
    ];
    for (const p of sslDisabled) {
      matches.push(...findMatches(content, p, missingDBEncryption, filePath, () =>
        "Enable SSL/TLS for database connections: { ssl: { rejectUnauthorized: true } }. In production, always verify server certificates."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC051 – GraphQL Introspection Enabled
// ────────────────────────────────────────────

const graphqlIntrospection: CustomRule = {
  id: "VC051",
  title: "GraphQL Introspection Enabled in Production",
  severity: "medium",
  category: "Information Leakage",
  description: "GraphQL introspection exposes your entire API schema, types, queries, and mutations to attackers, making it easy to find attack vectors.",
  check(content, filePath) {
    if (!/graphql/i.test(content) && !/graphql/i.test(filePath)) return [];
    const matches: RuleMatch[] = [];
    // Introspection explicitly enabled or not disabled
    if (/introspection\s*:\s*true/i.test(content)) {
      matches.push(...findMatches(content, /introspection\s*:\s*true/gi, graphqlIntrospection, filePath, () =>
        "Disable GraphQL introspection in production: introspection: process.env.NODE_ENV !== 'production'. This prevents schema exposure."
      ));
    }
    // GraphQL server setup without introspection config
    if (/(?:ApolloServer|GraphQLServer|createYoga|buildSchema|makeExecutableSchema)\s*\(/i.test(content)) {
      if (!/introspection/i.test(content)) {
        matches.push(...findMatches(content, /(?:ApolloServer|GraphQLServer|createYoga)\s*\(/gi, graphqlIntrospection, filePath, () =>
          "Explicitly disable introspection in production: new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })"
        ));
      }
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC052 – Missing Request Size Limit
// ────────────────────────────────────────────

const missingRequestSizeLimit: CustomRule = {
  id: "VC052",
  title: "Missing Request Body Size Limit",
  severity: "medium",
  category: "Availability",
  description: "Express/Hono/Fastify servers without request body size limits are vulnerable to denial-of-service via oversized payloads that exhaust memory.",
  check(content, filePath) {
    if (!/(?:server|app|index|main)\.[jt]sx?$/.test(filePath)) return [];
    if (!/(?:express|hono|fastify|koa)/i.test(content)) return [];
    const matches: RuleMatch[] = [];
    // express.json() without limit
    if (/express\.json\s*\(\s*\)/g.test(content)) {
      matches.push(...findMatches(content, /express\.json\s*\(\s*\)/g, missingRequestSizeLimit, filePath, () =>
        "Set a body size limit: express.json({ limit: '1mb' }). Without this, attackers can send huge payloads to crash your server."
      ));
    }
    // bodyParser without limit
    if (/bodyParser\.json\s*\(\s*\)/g.test(content)) {
      matches.push(...findMatches(content, /bodyParser\.json\s*\(\s*\)/g, missingRequestSizeLimit, filePath, () =>
        "Set a body size limit: bodyParser.json({ limit: '1mb' })."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC053 – Hardcoded IP/Host Allowlist
// ────────────────────────────────────────────

const hardcodedIPAllowlist: CustomRule = {
  id: "VC053",
  title: "Hardcoded IP or Host Allowlist",
  severity: "medium",
  category: "Configuration",
  description: "Hardcoded IP addresses or hostnames in allowlists are brittle and hard to update. They should be in environment variables or configuration files.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock") || filePath.match(/\.(md|txt)$/)) return [];
    const matches: RuleMatch[] = [];
    // Arrays of IPs used in access control
    const patterns = [
      /(?:allowedIPs|allowed_ips|whitelist|allowlist|trustedHosts)\s*[:=]\s*\[\s*["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
      /(?:allowedIPs|allowed_ips|whitelist|allowlist|trustedHosts)\s*[:=]\s*\[\s*["'`][\w.-]+\.(?:com|net|org|io)/gi,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, hardcodedIPAllowlist, filePath, () =>
        "Move IP/host allowlists to environment variables or a config file: const allowed = process.env.ALLOWED_IPS?.split(',') || [];"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC054 – Sensitive Data in localStorage
// ────────────────────────────────────────────

const sensitiveLocalStorage: CustomRule = {
  id: "VC054",
  title: "Sensitive Data in localStorage",
  severity: "high",
  category: "Secrets",
  description: "Storing tokens, passwords, or secrets in localStorage is insecure — it's accessible to any JavaScript on the page (XSS) and persists indefinitely. Use httpOnly cookies instead.",
  check(content, filePath) {
    if (!filePath.match(/\.(jsx?|tsx?|vue|svelte)$/)) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      /localStorage\.setItem\s*\(\s*["'`](?:token|access_token|auth_token|jwt|session|refresh_token|api_key|password|secret)/gi,
      /localStorage\s*\[\s*["'`](?:token|access_token|auth_token|jwt|session|refresh_token|api_key|password|secret)/gi,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, sensitiveLocalStorage, filePath, () =>
        "Don't store tokens/secrets in localStorage — use httpOnly cookies instead. localStorage is accessible to any XSS attack. For session tokens, set them as httpOnly, secure, sameSite cookies."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC055 – Exposed Source Maps in Production
// ────────────────────────────────────────────

const exposedSourceMaps: CustomRule = {
  id: "VC055",
  title: "Source Maps Exposed in Production",
  severity: "medium",
  category: "Information Leakage",
  description: "Source map files (.map) in production expose your original source code, comments, and internal logic to anyone who downloads them.",
  check(content, filePath) {
    // Check build configs for source maps in production
    if (!filePath.match(/(?:webpack|vite|rollup|next)\.config|tsconfig/i)) return [];
    const matches: RuleMatch[] = [];
    // Source maps enabled without environment check
    if (/(?:sourceMap|source-map|sourcemap)\s*[:=]\s*true/i.test(content)) {
      const hasEnvCheck = /process\.env\.NODE_ENV|NODE_ENV|production/i.test(content);
      if (!hasEnvCheck) {
        matches.push(...findMatches(content, /(?:sourceMap|source-map|sourcemap)\s*[:=]\s*true/gi, exposedSourceMaps, filePath, () =>
          "Disable source maps in production builds: sourceMap: process.env.NODE_ENV !== 'production'. Or use 'hidden-source-map' to generate maps without exposing them."
        ));
      }
    }
    // productionSourceMap in Vue
    if (/productionSourceMap\s*:\s*true/i.test(content)) {
      matches.push(...findMatches(content, /productionSourceMap\s*:\s*true/gi, exposedSourceMaps, filePath, () =>
        "Set productionSourceMap: false to avoid exposing source code in production."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC056 – Clickjacking / Missing X-Frame-Options
// ────────────────────────────────────────────

const clickjacking: CustomRule = {
  id: "VC056",
  title: "Clickjacking — Missing X-Frame-Options",
  severity: "medium",
  category: "Configuration",
  description: "Without X-Frame-Options or frame-ancestors CSP directive, your page can be embedded in an attacker's iframe for UI redress (clickjacking) attacks.",
  check(content, filePath) {
    // Check HTML files
    if (filePath.match(/\.(html|htm)$/)) {
      if (!/X-Frame-Options|frame-ancestors/i.test(content)) {
        return [{
          rule: "VC056", title: clickjacking.title, severity: "medium" as const, category: "Configuration",
          file: filePath, line: 1, snippet: getSnippet(content, 1),
          fix: 'Add <meta http-equiv="X-Frame-Options" content="DENY"> or set frame-ancestors in CSP to prevent clickjacking.'
        }];
      }
    }
    // Check server configs
    if (/(?:server|app|index|main)\.[jt]sx?$/.test(filePath)) {
      if (/(?:express|hono|fastify|koa)/i.test(content)) {
        if (!/X-Frame-Options|frame-ancestors|helmet/i.test(content)) {
          return findMatches(content, /(?:express|hono|fastify|koa)\s*\(/gi, clickjacking, filePath, () =>
            "Add X-Frame-Options header: res.setHeader('X-Frame-Options', 'DENY'). Or use helmet: app.use(helmet()) which sets this and other security headers."
          );
        }
      }
    }
    return [];
  },
};

// ────────────────────────────────────────────
// VC057 – Overly Permissive IAM/Cloud Roles
// ────────────────────────────────────────────

const overlyPermissiveIAM: CustomRule = {
  id: "VC057",
  title: "Overly Permissive IAM/Cloud Permissions",
  severity: "critical",
  category: "Authorization",
  description: "Wildcard (*) permissions in AWS IAM, GCP, or Terraform configs grant unrestricted access, violating the principle of least privilege.",
  check(content, filePath) {
    if (!filePath.match(/\.(tf|hcl|json|yaml|yml)$/) && !filePath.match(/(?:iam|policy|role|permission)/i)) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      // AWS IAM wildcard
      /["'`]Action["'`]\s*:\s*["'`]\*["'`]/g,
      /["'`]Resource["'`]\s*:\s*["'`]\*["'`]/g,
      // Terraform aws_iam
      /actions\s*=\s*\[\s*["'`]\*["'`]\s*\]/g,
      /resources\s*=\s*\[\s*["'`]\*["'`]\s*\]/g,
      // GCP bindings
      /role\s*[:=]\s*["'`]roles\/(?:owner|editor)["'`]/g,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, overlyPermissiveIAM, filePath, () =>
        "Follow the principle of least privilege: replace wildcard (*) with specific actions and resources. Example: 'Action': 's3:GetObject' instead of '*'."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC058 – Docker Running as Root
// ────────────────────────────────────────────

const dockerRunAsRoot: CustomRule = {
  id: "VC058",
  title: "Docker Container Running as Root",
  severity: "high",
  category: "Configuration",
  description: "Containers running as root give attackers full system access if they escape the container. Always run as a non-root user.",
  check(content, filePath) {
    if (!filePath.match(/Dockerfile$/i)) return [];
    const hasUser = /^\s*USER\s+/m.test(content);
    if (hasUser) return [];
    return [{
      rule: "VC058", title: dockerRunAsRoot.title, severity: "high" as const, category: "Configuration",
      file: filePath, line: 1, snippet: getSnippet(content, 1),
      fix: "Add a USER directive: RUN addgroup -S app && adduser -S app -G app\\nUSER app. Place it after installing dependencies but before COPY/CMD."
    }];
  },
};

// ────────────────────────────────────────────
// VC059 – Exposed Ports in Docker Compose
// ────────────────────────────────────────────

const exposedDockerPorts: CustomRule = {
  id: "VC059",
  title: "Docker Compose Binding to All Interfaces",
  severity: "medium",
  category: "Configuration",
  description: "Binding ports to 0.0.0.0 (default) in Docker Compose exposes services to the entire network. Bind to 127.0.0.1 for local-only access.",
  check(content, filePath) {
    if (!filePath.match(/docker-compose|compose\.(yaml|yml)$/i)) return [];
    const matches: RuleMatch[] = [];
    // ports: "3000:3000" or "8080:80" without binding to 127.0.0.1
    const portPattern = /ports:\s*\n(?:\s*-\s*["'`]?\d+:\d+["'`]?\s*\n?)+/g;
    if (portPattern.test(content) && !/127\.0\.0\.1:/i.test(content)) {
      matches.push(...findMatches(content, /^\s*-\s*["'`]?\d+:\d+["'`]?/gm, exposedDockerPorts, filePath, () =>
        "Bind to localhost only: '127.0.0.1:3000:3000' instead of '3000:3000'. This prevents external network access to the service."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC060 – Weak Hashing Algorithm
// ────────────────────────────────────────────

const weakHashing: CustomRule = {
  id: "VC060",
  title: "Weak Hashing Algorithm for Passwords",
  severity: "critical",
  category: "Cryptography",
  description: "MD5 and SHA1/SHA256 are too fast for password hashing — they can be brute-forced at billions of attempts per second. Use bcrypt, scrypt, or argon2 instead.",
  check(content, filePath) {
    if (filePath.includes("test") || filePath.includes("mock")) return [];
    const matches: RuleMatch[] = [];
    // MD5/SHA used with password context
    const patterns = [
      /(?:md5|sha1|sha256|sha512)\s*\([^)]*(?:password|passwd|pwd)/gi,
      /createHash\s*\(\s*["'`](?:md5|sha1|sha256)["'`]\).*(?:password|passwd|pwd)/gi,
      /(?:password|passwd|pwd).*createHash\s*\(\s*["'`](?:md5|sha1|sha256)["'`]\)/gi,
      /hashlib\.(?:md5|sha1|sha256)\s*\([^)]*(?:password|passwd|pwd)/gi,
      /Digest::(?:MD5|SHA1|SHA256).*(?:password|passwd|pwd)/gi,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, weakHashing, filePath, () =>
        "Use bcrypt, scrypt, or argon2 for password hashing — they're intentionally slow. Example: const hash = await bcrypt.hash(password, 12);"
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC061 – Disabled TLS Certificate Verification
// ────────────────────────────────────────────

const disabledTLSVerification: CustomRule = {
  id: "VC061",
  title: "Disabled TLS Certificate Verification",
  severity: "critical",
  category: "Cryptography",
  description: "Disabling TLS certificate verification (NODE_TLS_REJECT_UNAUTHORIZED=0 or rejectUnauthorized:false) makes all HTTPS connections vulnerable to man-in-the-middle attacks.",
  check(content, filePath) {
    const matches: RuleMatch[] = [];
    const patterns = [
      /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["'`]?0["'`]?/g,
      /rejectUnauthorized\s*:\s*false/g,
      /verify\s*[:=]\s*false.*(?:ssl|tls|cert|https)/gi,
      /PYTHONHTTPSVERIFY\s*[:=]\s*["'`]?0["'`]?/g,
      /ssl_verify\s*[:=]\s*false/gi,
      /InsecureSkipVerify\s*:\s*true/g,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, disabledTLSVerification, filePath, () =>
        "Never disable TLS certificate verification in production. Fix the root cause: install the correct CA certificate, or use NODE_EXTRA_CA_CERTS for custom CAs."
      ));
    }
    return matches;
  },
};

// ────────────────────────────────────────────
// VC062 – Hardcoded Encryption Key/IV
// ────────────────────────────────────────────

const hardcodedEncryptionKey: CustomRule = {
  id: "VC062",
  title: "Hardcoded Encryption Key or IV",
  severity: "critical",
  category: "Cryptography",
  description: "Hardcoded encryption keys and initialization vectors (IVs) in source code can be extracted to decrypt all data. IVs must be random per encryption operation.",
  check(content, filePath) {
    if (filePath.endsWith(".example") || filePath.endsWith(".template") || filePath.includes("test")) return [];
    const matches: RuleMatch[] = [];
    const patterns = [
      // Encryption key as string literal
      /(?:encryption_key|encryptionKey|cipher_key|cipherKey|aes_key|AES_KEY|ENCRYPTION_KEY)\s*[:=]\s*["'`][^"'`]{8,}["'`]/g,
      // createCipheriv with hardcoded key
      /createCipher(?:iv)?\s*\(\s*["'`][^"'`]+["'`]\s*,\s*["'`][^"'`]+["'`]/g,
      // Buffer.from with hardcoded key near cipher
      /(?:key|iv|nonce)\s*[:=]\s*Buffer\.from\s*\(\s*["'`][^"'`]{8,}["'`]/gi,
      // Static IV (should be random)
      /(?:iv|nonce|initialVector)\s*[:=]\s*["'`][^"'`]{8,}["'`]/gi,
    ];
    for (const p of patterns) {
      matches.push(...findMatches(content, p, hardcodedEncryptionKey, filePath, () =>
        "Move encryption keys to environment variables. Generate IVs randomly per operation: crypto.randomBytes(16). Never reuse IVs."
      ));
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
  insecureDeserialization,
  hardcodedJWTSecret,
  missingHTTPS,
  exposedDebugMode,
  insecureRandomness,
  openRedirectParams,
  missingErrorBoundary,
  exposedStackTraces,
  insecureFileUpload,
  missingLockFile,
  exposedGitDir,
  ssrfVulnerability,
  massAssignment,
  timingAttack,
  logInjection,
  weakPasswordRequirements,
  sessionFixation,
  missingBruteForce,
  nosqlInjection,
  exposedDBCredentials,
  missingDBEncryption,
  graphqlIntrospection,
  missingRequestSizeLimit,
  hardcodedIPAllowlist,
  sensitiveLocalStorage,
  exposedSourceMaps,
  clickjacking,
  overlyPermissiveIAM,
  dockerRunAsRoot,
  exposedDockerPorts,
  weakHashing,
  disabledTLSVerification,
  hardcodedEncryptionKey,
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
