import { resolve, join } from "node:path";
import ora from "ora";
import chalk from "chalk";
import type { Finding, ScanOptions, ScanResult } from "../types.js";
import { collectFiles, readFileContents } from "../utils/files.js";
import { loadConfig } from "../utils/config.js";
import { runCustomRules } from "../scanners/custom-rules.js";
import { runSemgrep } from "../scanners/semgrep.js";
import { runGitleaks } from "../scanners/gitleaks.js";
import { analyzeWithAI } from "../scanners/ai-analyzer.js";
import { renderTerminalReport } from "../reporters/terminal.js";
import { renderJsonReport } from "../reporters/json.js";
import { renderSarifReport } from "../reporters/sarif.js";
import { checkUsage, incrementUsage, uploadScanResults, isAuthenticated } from "../utils/api.js";

export async function scanCommand(
  directory: string,
  options: Partial<ScanOptions>,
): Promise<void> {
  const dir = resolve(directory || ".");
  const format = options.format ?? "terminal";
  const verbose = options.verbose ?? false;
  const startTime = Date.now();

  // Load config
  const config = await loadConfig(dir);
  const useAI = (options.aiAnalysis ?? config.ai ?? true) && !!process.env.ANTHROPIC_API_KEY;

  const isSilent = format !== "terminal";

  // Step 0: Check usage limits (if authenticated)
  if (isAuthenticated()) {
    const usage = await checkUsage();
    if (!usage.allowed) {
      console.log(chalk.red("\nDaily scan limit reached (3/3 scans used)."));
      console.log(chalk.yellow("Upgrade to Pro for unlimited scans: ") + chalk.bold("vibecheck upgrade"));
      console.log(chalk.gray(`Resets tomorrow. Plan: ${usage.plan}\n`));
      process.exitCode = 1;
      return;
    }
    if (usage.plan === "free" && usage.remaining > 0 && usage.remaining <= 2 && !isSilent) {
      console.log(chalk.gray(`  ${usage.remaining} free scan${usage.remaining === 1 ? "" : "s"} remaining today\n`));
    }
  }

  // Step 1: Collect files
  const spinner = ora({
    text: "Scanning files...",
    color: "cyan",
    isSilent,
  }).start();

  let files: string[];
  try {
    files = await collectFiles(dir);
  } catch (error) {
    spinner.fail("Failed to scan directory");
    console.error(chalk.red(`Error: ${error instanceof Error ? error.message : error}`));
    process.exit(1);
  }

  if (files.length === 0) {
    spinner.warn("No source files found in this directory");
    return;
  }

  spinner.text = `Found ${files.length} files. Running security rules...`;

  // Step 2: Run all static scanners in parallel
  const allFindings: Finding[] = [];

  // 2a: Custom rules (always runs, instant)
  for (const filePath of files) {
    const content = readFileContents(dir, filePath);
    if (!content) continue;
    const findings = runCustomRules(content, filePath, config.disableRules);
    allFindings.push(...findings);
  }

  const customCount = allFindings.length;
  if (verbose && customCount > 0) {
    spinner.info(`Custom rules found ${customCount} issues`);
  }

  // 2b: Semgrep + Gitleaks (run in parallel, gracefully skip if not installed)
  spinner.text = "Running external scanners...";
  spinner.color = "yellow";

  // Resolve custom rules directory (shipped with vibecheck)
  const rulesDir = resolve(join(import.meta.dirname, "../../rules"));
  const fallbackRulesDir = resolve(join(dir, "../rules"));

  const [semgrepResult, gitleaksResult] = await Promise.allSettled([
    runSemgrep(dir, rulesDir).catch(() => runSemgrep(dir, fallbackRulesDir)).catch(() => ({ findings: [] as Finding[], available: false })),
    runGitleaks(dir).catch(() => ({ findings: [] as Finding[], available: false })),
  ]);

  const semgrep = semgrepResult.status === "fulfilled" ? semgrepResult.value : { findings: [], available: false };
  const gitleaks = gitleaksResult.status === "fulfilled" ? gitleaksResult.value : { findings: [], available: false };

  allFindings.push(...semgrep.findings);
  allFindings.push(...gitleaks.findings);

  if (verbose) {
    if (semgrep.available) {
      spinner.info(`Semgrep found ${semgrep.findings.length} issues`);
    } else {
      spinner.info(chalk.gray("Semgrep not installed — install with: pip install semgrep"));
    }
    if (gitleaks.available) {
      spinner.info(`Gitleaks found ${gitleaks.findings.length} issues`);
    } else {
      spinner.info(chalk.gray("Gitleaks not installed — install with: brew install gitleaks"));
    }
  }

  // Show install hints for missing tools (non-verbose, terminal only)
  if (!isSilent && !verbose) {
    const missing: string[] = [];
    if (!semgrep.available) missing.push("semgrep (pip install semgrep)");
    if (!gitleaks.available) missing.push("gitleaks (brew install gitleaks)");
    if (missing.length > 0) {
      spinner.info(chalk.gray(`Optional: install ${missing.join(" and ")} for deeper scanning`));
    }
  }

  const staticCount = allFindings.length;
  spinner.text = `Static analysis found ${staticCount} issue${staticCount !== 1 ? "s" : ""}`;

  // Step 3: AI analysis (if enabled)
  if (useAI) {
    spinner.text = "Running AI analysis...";
    spinner.color = "magenta";

    try {
      const priorityFiles = files
        .map((path) => ({
          path,
          content: readFileContents(dir, path) ?? "",
        }))
        .filter((f) => f.content.length > 0 && f.content.length < 30_000)
        .filter((f) => {
          const isHighPriority =
            /(?:api|server|route|auth|middleware|webhook|payment|stripe|supabase)/i.test(f.path) ||
            allFindings.some((finding) => finding.file === f.path) ||
            /(?:query|execute|fetch|prisma|drizzle|mongoose)/i.test(f.content);
          return isHighPriority;
        })
        .slice(0, 20);

      if (priorityFiles.length > 0) {
        const aiFindings = await analyzeWithAI(priorityFiles, allFindings);
        allFindings.push(...aiFindings);

        if (verbose && aiFindings.length > 0) {
          spinner.info(`AI analysis found ${aiFindings.length} additional issues`);
        }
      }
    } catch (error) {
      if (error instanceof Error) {
        spinner.warn(`AI analysis skipped: ${error.message}`);
      }
    }
  } else if (!process.env.ANTHROPIC_API_KEY && !isSilent) {
    spinner.info(
      chalk.gray("Tip: Set ANTHROPIC_API_KEY for AI-powered contextual analysis"),
    );
  }

  spinner.stop();

  // Step 4: Deduplicate findings (same file + line + similar rule)
  const seen = new Set<string>();
  const dedupedFindings = allFindings.filter((f) => {
    // Normalize: group by file:line and a simplified rule key
    const ruleKey = f.source === "gitleaks" ? `secret:${f.file}:${f.line}` : `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(ruleKey)) return false;
    seen.add(ruleKey);
    return true;
  });

  // Step 5: Render results
  const result: ScanResult = {
    findings: dedupedFindings,
    filesScanned: files.length,
    duration: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    directory: dir,
  };

  switch (format) {
    case "json":
      renderJsonReport(result);
      break;
    case "sarif":
      renderSarifReport(result);
      break;
    default:
      renderTerminalReport(result);
      break;
  }

  // Step 6: Upload results and increment usage (if authenticated)
  if (isAuthenticated()) {
    await Promise.allSettled([
      incrementUsage(),
      uploadScanResults({
        directory: dir,
        filesScanned: files.length,
        findings: dedupedFindings,
        duration: Date.now() - startTime,
      }),
    ]);
  }

  // Exit with error code if critical/high findings exist
  const hasCritical = dedupedFindings.some(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  if (hasCritical) {
    process.exitCode = 1;
  }
}
