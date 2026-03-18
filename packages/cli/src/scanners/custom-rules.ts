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
