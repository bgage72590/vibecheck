export interface ScanSummary {
  id: string;
  directory: string;
  filesScanned: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  duration: number;
  createdAt: string;
}

export interface Finding {
  id: string;
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file: string;
  line: number;
  snippet: string;
  fix?: string;
  fixCode?: { before: string; after: string };
  category: string;
  source: "custom" | "semgrep" | "gitleaks" | "ai";
  owasp?: string;
  cwe?: string;
}

export const demoScans: ScanSummary[] = [
  {
    id: "scan-1",
    directory: "/app/my-saas",
    filesScanned: 47,
    findingsCount: 11,
    criticalCount: 7,
    highCount: 3,
    mediumCount: 1,
    lowCount: 0,
    duration: 2340,
    createdAt: "2026-03-18T14:30:00Z",
  },
  {
    id: "scan-2",
    directory: "/app/my-saas",
    filesScanned: 47,
    findingsCount: 8,
    criticalCount: 4,
    highCount: 3,
    mediumCount: 1,
    lowCount: 0,
    duration: 2100,
    createdAt: "2026-03-17T10:15:00Z",
  },
  {
    id: "scan-3",
    directory: "/app/landing-page",
    filesScanned: 12,
    findingsCount: 3,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 1,
    lowCount: 0,
    duration: 890,
    createdAt: "2026-03-16T09:00:00Z",
  },
  {
    id: "scan-4",
    directory: "/app/my-saas",
    filesScanned: 45,
    findingsCount: 15,
    criticalCount: 9,
    highCount: 4,
    mediumCount: 2,
    lowCount: 0,
    duration: 3200,
    createdAt: "2026-03-15T16:45:00Z",
  },
  {
    id: "scan-5",
    directory: "/app/my-saas",
    filesScanned: 44,
    findingsCount: 18,
    criticalCount: 11,
    highCount: 5,
    mediumCount: 2,
    lowCount: 0,
    duration: 3500,
    createdAt: "2026-03-14T11:30:00Z",
  },
];

export const demoFindings: Finding[] = [
  {
    id: "f1",
    rule: "VC001",
    severity: "critical",
    title: "Hardcoded API Key or Secret",
    description: "API keys, tokens, or secrets hardcoded in source code can be extracted by anyone with access to the code.",
    file: ".env",
    line: 1,
    snippet: '>    1 | DATABASE_URL=postgres://admin:****@db.example.com:5432/myapp\n     2 | SUPABASE_ANON_KEY=eyJ...\n     3 | STRIPE_SECRET_KEY=sk_live_****',
    fix: "Move this secret to an environment variable and add it to .env (not committed to git).",
    category: "Secrets",
    source: "custom",
  },
  {
    id: "f2",
    rule: "VC005",
    severity: "critical",
    title: "Unprotected Stripe Webhook Endpoint",
    description: "Stripe webhook endpoints without signature verification allow attackers to fake payment events.",
    file: "server.js",
    line: 39,
    snippet: '    37 | \n    38 | // Stripe webhook\n>   39 | app.post("/api/webhooks/stripe", async (req, res) => {\n    40 |   const event = req.body;',
    fix: "Verify the Stripe webhook signature using stripe.webhooks.constructEvent().",
    category: "Payment Security",
    source: "custom",
  },
  {
    id: "f3",
    rule: "VC006",
    severity: "critical",
    title: "Potential SQL Injection",
    description: "String concatenation in SQL queries allows attackers to execute arbitrary database commands.",
    file: "server.js",
    line: 34,
    snippet: "    32 |   });\n    33 |   // raw SQL\n>   34 |   const result = await db.query(`SELECT * FROM products WHERE name LIKE '%${query}%'`);\n    35 |   res.json(result);",
    fix: "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])",
    category: "Injection",
    source: "custom",
  },
  {
    id: "f4",
    rule: "VC007",
    severity: "high",
    title: "Potential Cross-Site Scripting (XSS)",
    description: "Rendering user input without sanitization allows attackers to inject malicious scripts.",
    file: "Dashboard.tsx",
    line: 29,
    snippet: '    27 |         <div\n    28 |           key={u.id}\n>   29 |           dangerouslySetInnerHTML={{ __html: u.bio }}\n    30 |         />',
    fix: "Sanitize user input before rendering: DOMPurify.sanitize(userInput)",
    category: "Injection",
    source: "custom",
  },
  {
    id: "f5",
    rule: "VC009",
    severity: "medium",
    title: "CORS Allows All Origins",
    description: "Wildcard CORS allows any website to make requests to your API.",
    file: "server.js",
    line: 9,
    snippet: "     7 | \n     8 | // CORS\n>    9 | app.use(cors());\n    10 | ",
    fix: "Restrict CORS: cors({ origin: 'https://yourdomain.com' })",
    category: "Configuration",
    source: "custom",
  },
];

export const trendData = [
  { date: "Mar 14", critical: 11, high: 5, medium: 2 },
  { date: "Mar 15", critical: 9, high: 4, medium: 2 },
  { date: "Mar 16", critical: 8, high: 3, medium: 1 },
  { date: "Mar 17", critical: 4, high: 3, medium: 1 },
  { date: "Mar 18", critical: 7, high: 3, medium: 1 },
];
