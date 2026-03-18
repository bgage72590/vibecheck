import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding, Severity } from "../types.js";

interface SemgrepSarifResult {
  runs?: Array<{
    results?: Array<{
      ruleId?: string;
      level?: string;
      message?: { text?: string };
      locations?: Array<{
        physicalLocation?: {
          artifactLocation?: { uri?: string };
          region?: {
            startLine?: number;
            startColumn?: number;
            snippet?: { text?: string };
          };
        };
      }>;
    }>;
  }>;
}

const SEVERITY_MAP: Record<string, Severity> = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "info",
};

function semgrepSeverityToVibecheck(level: string): Severity {
  return SEVERITY_MAP[level] ?? "medium";
}

async function isSemgrepInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile("semgrep", ["--version"], (error) => {
      resolve(!error);
    });
  });
}

export async function runSemgrep(
  directory: string,
  customRulesDir?: string,
): Promise<{ findings: Finding[]; available: boolean }> {
  const installed = await isSemgrepInstalled();
  if (!installed) {
    return { findings: [], available: false };
  }

  const findings: Finding[] = [];

  // Create a temp directory for SARIF output
  const tmpDir = await mkdtemp(join(tmpdir(), "vibecheck-semgrep-"));
  const sarifPath = join(tmpDir, "results.sarif");

  try {
    // Build semgrep args
    const args = [
      "scan",
      "--sarif",
      "--output", sarifPath,
      "--quiet",
      "--no-git-ignore", // We handle .gitignore ourselves
      "--timeout", "30",
      "--max-target-bytes", "1000000",
    ];

    // Use auto config (community rules) + custom rules if available
    args.push("--config", "auto");

    if (customRulesDir && existsSync(customRulesDir)) {
      args.push("--config", customRulesDir);
    }

    args.push(directory);

    // Run semgrep
    await new Promise<void>((resolve, reject) => {
      const proc = execFile(
        "semgrep",
        args,
        { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
        (error, _stdout, stderr) => {
          // Semgrep returns exit code 1 when findings exist — that's fine
          if (error && error.code !== 1) {
            reject(new Error(`Semgrep failed: ${stderr || error.message}`));
          } else {
            resolve();
          }
        },
      );
    });

    // Parse SARIF output
    if (!existsSync(sarifPath)) return { findings, available: true };

    const sarifContent = await readFile(sarifPath, "utf-8");
    const sarif: SemgrepSarifResult = JSON.parse(sarifContent);

    for (const run of sarif.runs ?? []) {
      for (const result of run.results ?? []) {
        const location = result.locations?.[0]?.physicalLocation;
        const filePath = location?.artifactLocation?.uri ?? "unknown";
        const line = location?.region?.startLine ?? 1;
        const snippet = location?.region?.snippet?.text ?? "";

        // Determine category from rule ID
        const ruleId = result.ruleId ?? "semgrep";
        const category = categorizeSemgrepRule(ruleId);

        findings.push({
          id: `SG-${filePath}:${line}:${ruleId}`,
          rule: ruleId,
          severity: semgrepSeverityToVibecheck(result.level ?? "warning"),
          title: truncate(result.message?.text ?? ruleId, 100),
          description: result.message?.text ?? "",
          file: filePath.replace(/^file:\/\//, ""),
          line,
          column: location?.region?.startColumn,
          snippet: formatSnippet(snippet, line),
          category,
          source: "semgrep",
        });
      }
    }
  } finally {
    // Clean up temp directory
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }

  return { findings, available: true };
}

function categorizeSemgrepRule(ruleId: string): string {
  const id = ruleId.toLowerCase();
  if (id.includes("sql") || id.includes("injection") || id.includes("xss") || id.includes("command")) return "Injection";
  if (id.includes("auth") || id.includes("session")) return "Authentication";
  if (id.includes("crypto") || id.includes("hash") || id.includes("random")) return "Cryptography";
  if (id.includes("cors") || id.includes("header") || id.includes("config")) return "Configuration";
  if (id.includes("secret") || id.includes("key") || id.includes("password") || id.includes("credential")) return "Secrets";
  if (id.includes("path") || id.includes("traversal") || id.includes("file")) return "Path Traversal";
  if (id.includes("deserial")) return "Deserialization";
  return "Security";
}

function formatSnippet(text: string, line: number): string {
  if (!text) return "";
  const lines = text.split("\n");
  return lines
    .map((l, i) => {
      const num = line + i;
      return `  ${num.toString().padStart(4)} | ${l}`;
    })
    .join("\n");
}

function truncate(str: string, max: number): string {
  return str.length > max ? str.substring(0, max - 3) + "..." : str;
}
