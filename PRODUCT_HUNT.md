# Product Hunt Launch Copy

## Tagline (60 chars max)
**AI security scanner for vibe-coded apps**

## Description

### The Problem
45% of AI-generated code contains security vulnerabilities. Solo devs and non-technical founders are shipping apps built with Cursor, Lovable, Bolt, and Replit — with hardcoded API keys, missing authentication, SQL injection, and exposed databases. They don't know what they don't know.

### The Solution
VibeCheck scans your codebase with one command and tells you exactly what's wrong — in plain English, not security jargon.

```
npx vibecheck scan .
```

No config. No account. No security expertise required.

### What it catches
- Hardcoded API keys and secrets (AWS, Stripe, OpenAI, Supabase)
- API routes without authentication
- Supabase RLS bypass and exposed databases
- Unprotected Stripe webhook endpoints (attackers can fake payments)
- SQL injection and XSS vulnerabilities
- Client-side auth checks without server enforcement
- Wildcard CORS and missing rate limiting

### How it works
1. **Static rules** — 10 purpose-built rules for AI-generated code patterns
2. **AI analysis** — Claude reads your code in context and finds issues static rules miss
3. **Plain-English reports** — Every vulnerability explained with a specific fix

### Why we built it
We kept seeing the same story on Reddit: someone proudly ships their vibe-coded SaaS, then days later posts "guys, I'm under attack." We built the tool we wished they had.

---

## Maker's First Comment

Hey PH! I'm [name], and I built VibeCheck because I kept seeing the same horror story play out on r/vibecoding and r/cybersecurity:

1. Builder ships app built entirely with AI coding tools
2. Posts proudly on Twitter: "zero hand-written code!"
3. Days later: "guys, I'm under attack... people bypassing the subscription, maxed out API keys"

The most viral case was "Leo" — his entire SaaS got compromised because Cursor didn't add authentication, rate limiting, or input validation. He had no idea what any of those things were.

That's when I realized: AI coding tools are amazing at making things work, but terrible at making things secure. And the people using them don't have the security background to know what's missing.

So I built VibeCheck — one command that finds what's wrong and tells you how to fix it, in language anyone can understand. Instead of "IDOR via insecure direct object reference," we say "anyone can access other users' data by changing the ID in the URL."

**What's under the hood:**
- 10 custom security rules targeting vibe-code patterns (Supabase RLS, Stripe webhooks, etc.)
- Claude AI for contextual analysis that catches what static rules miss
- Optional Semgrep + Gitleaks integration for deeper scanning
- SARIF output for GitHub Code Scanning integration
- Built as an open-source CLI with a freemium SaaS model

Try it right now: `npx vibecheck scan .`

Would love your feedback — what rules should we add next?

---

## Screenshots to Include

1. **Terminal output** — The color-coded scan results showing critical/high/medium findings with code snippets and fix suggestions
2. **Dashboard** — The web dashboard with vulnerability trend chart and scan history table
3. **Landing page hero** — The "Stop shipping hackable code" hero section with terminal mockup
4. **Finding detail** — Close-up of a single finding card showing the Stripe webhook vulnerability with fix
5. **GitHub Action** — PR check showing VibeCheck results in the Security tab

## Categories
- Developer Tools
- Security
- Artificial Intelligence
- Open Source

## Topics
- AI code security
- Vibe coding
- Application security
- Developer tools
- SAST scanner
