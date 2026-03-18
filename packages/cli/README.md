# vibecheck

AI security scanner for vibe-coded apps. Find vulnerabilities before attackers do.

Built for solo devs and non-technical founders shipping AI-generated code via Cursor, Lovable, Bolt, Replit, and Claude Code.

## Quick Start

```bash
npx vibecheck scan .
```

That's it. No config needed.

## What It Catches

| Rule | Vulnerability | Severity |
|------|--------------|----------|
| VC001 | Hardcoded API keys & secrets (AWS, Stripe, OpenAI, Supabase, DB URLs) | Critical |
| VC002 | .env files with secrets committed to git | High |
| VC003 | API routes missing authentication | High |
| VC004 | Supabase service_role key in client code / RLS bypass | Critical |
| VC005 | Stripe webhooks without signature verification | Critical |
| VC006 | SQL injection via string interpolation | Critical |
| VC007 | XSS (dangerouslySetInnerHTML, innerHTML, v-html) | High |
| VC008 | Server without rate limiting | Medium |
| VC009 | Wildcard CORS configuration | Medium |
| VC010 | Client-side only authorization checks | High |

Plus **AI-powered contextual analysis** that catches issues static rules miss.

## Installation

```bash
# Run directly (no install)
npx vibecheck scan .

# Or install globally
npm install -g vibecheck
vibecheck scan .
```

## Usage

```bash
# Scan current directory
vibecheck scan .

# Scan a specific directory
vibecheck scan ./my-project

# Skip AI analysis (faster, no API key needed)
vibecheck scan . --no-ai

# JSON output (for CI pipelines)
vibecheck scan . --format json

# SARIF output (for GitHub Code Scanning)
vibecheck scan . --format sarif

# Verbose output (show per-scanner results)
vibecheck scan . -v
```

## AI-Powered Analysis

Set your Anthropic API key for deeper, contextual vulnerability analysis:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
vibecheck scan .
```

The AI analyzer understands your code in context and explains vulnerabilities in plain English with specific fix instructions.

## CI Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vibecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vibecheck/action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Results appear in the GitHub Security tab.

### Any CI

```bash
npx vibecheck scan . --format sarif --no-ai > results.sarif
```

Exit code is 1 when critical or high severity issues are found.

## Configuration

Create a `.vibecheckrc.json` in your project root:

```json
{
  "exclude": ["tests/**", "scripts/**"],
  "ai": true,
  "severity": "medium",
  "disableRules": ["VC008"]
}
```

## Optional: Deeper Scanning

Install these tools for additional detection coverage:

```bash
# Semgrep - 2000+ community security rules
pip install semgrep

# Gitleaks - advanced secret detection
brew install gitleaks
```

VibeCheck automatically uses them if available.

## Auth & Pro Plan

```bash
# Log in to sync scan history
vibecheck auth login

# Check your plan
vibecheck auth whoami

# Upgrade to Pro ($29/mo) for unlimited scans
vibecheck upgrade
```

Free plan: 3 scans/day. Pro: unlimited scans, scan history, team features.

## License

MIT
