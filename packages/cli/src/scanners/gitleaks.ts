import { execFile } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding, Severity } from "../types.js";
import { getSnippet, readFileContents } from "../utils/files.js";

interface GitleaksResult {
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  RuleID: string;
  Entropy: number;
  Tags?: string[];
}

const RULE_SEVERITY: Record<string, Severity> = {
  "aws-access-token": "critical",
  "aws-secret-access-key": "critical",
  "stripe-access-token": "critical",
  "github-pat": "critical",
  "private-key": "critical",
  "generic-api-key": "high",
  "slack-webhook": "high",
  "twilio-api-key": "high",
  "sendgrid-api-key": "high",
  "shopify-access-token": "high",
  "gcp-api-key": "critical",
  "heroku-api-key": "high",
  "npm-access-token": "critical",
  "pypi-upload-token": "critical",
  "telegram-bot-api-token": "high",
  "discord-bot-token": "high",
  "firebase-api-key": "high",
};

async function isGitleaksInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile("gitleaks", ["version"], (error) => {
      resolve(!error);
    });
  });
}

export async function runGitleaks(
  directory: string,
): Promise<{ findings: Finding[]; available: boolean }> {
  const installed = await isGitleaksInstalled();
  if (!installed) {
    return { findings: [], available: false };
  }

  const findings: Finding[] = [];
  const tmpDir = await mkdtemp(join(tmpdir(), "vibecheck-gitleaks-"));
  const reportPath = join(tmpDir, "results.json");

  try {
    const args = [
      "detect",
      "--source", directory,
      "--report-path", reportPath,
      "--report-format", "json",
      "--no-git",
      "--exit-code", "0", // Don't fail on findings
    ];

    await new Promise<void>((resolve, reject) => {
      execFile(
        "gitleaks",
        args,
        { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
        (error, _stdout, stderr) => {
          if (error) {
            reject(new Error(`Gitleaks failed: ${stderr || error.message}`));
          } else {
            resolve();
          }
        },
      );
    });

    // Parse results
    if (!existsSync(reportPath)) return { findings, available: true };

    const reportContent = await readFile(reportPath, "utf-8");
    if (!reportContent.trim()) return { findings, available: true };

    const results: GitleaksResult[] = JSON.parse(reportContent);

    for (const result of results) {
      const filePath = result.File;
      const line = result.StartLine + 1; // Gitleaks uses 0-based lines
      const severity = RULE_SEVERITY[result.RuleID] ?? "high";

      // Read file content for snippet
      const content = readFileContents(directory, filePath);
      const snippet = content ? getSnippet(content, line) : `  ${result.Match}`;

      // Redact the actual secret in the description
      const redactedSecret = result.Secret.length > 8
        ? result.Secret.substring(0, 4) + "..." + result.Secret.substring(result.Secret.length - 4)
        : "****";

      findings.push({
        id: `GL-${filePath}:${line}:${result.RuleID}`,
        rule: `GL:${result.RuleID}`,
        severity,
        title: `${result.Description} (detected by Gitleaks)`,
        description: `A secret matching "${result.RuleID}" pattern was found: ${redactedSecret}. If this is a real credential, it may already be compromised. Rotate it immediately and move it to environment variables.`,
        file: filePath,
        line,
        column: result.StartColumn,
        snippet,
        fix: `1. Rotate this credential immediately (it may be in git history)\n2. Move it to a .env file: ${result.RuleID.toUpperCase().replace(/-/g, "_")}=<new-value>\n3. Add .env to .gitignore\n4. Remove from git history: git filter-branch or BFG Repo Cleaner`,
        category: "Secrets",
        source: "gitleaks",
      });
    }
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }

  return { findings, available: true };
}
