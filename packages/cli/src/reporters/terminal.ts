import chalk from "chalk";
import Table from "cli-table3";
import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "!!!",
  high: " !! ",
  medium: " ! ",
  low: " - ",
  info: " i ",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function renderTerminalReport(result: ScanResult): void {
  const { findings, filesScanned, duration } = result;

  // Header
  console.log("");
  console.log(chalk.bold.cyan("  vibecheck") + chalk.gray(" — security scan results"));
  console.log(chalk.gray("  " + "─".repeat(50)));
  console.log("");

  if (findings.length === 0) {
    console.log(chalk.green.bold("  No vulnerabilities found!"));
    console.log(chalk.gray(`  Scanned ${filesScanned} files in ${(duration / 1000).toFixed(1)}s`));
    console.log("");
    return;
  }

  // Sort by severity
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );

  // Summary table
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  const summaryParts: string[] = [];
  if (counts.critical > 0) summaryParts.push(chalk.bgRed.white.bold(` ${counts.critical} CRITICAL `));
  if (counts.high > 0) summaryParts.push(chalk.red.bold(`${counts.high} high`));
  if (counts.medium > 0) summaryParts.push(chalk.yellow.bold(`${counts.medium} medium`));
  if (counts.low > 0) summaryParts.push(chalk.blue(`${counts.low} low`));
  if (counts.info > 0) summaryParts.push(chalk.gray(`${counts.info} info`));

  console.log(`  Found ${chalk.bold(findings.length.toString())} issues: ${summaryParts.join(chalk.gray(" | "))}`);
  console.log(chalk.gray(`  Scanned ${filesScanned} files in ${(duration / 1000).toFixed(1)}s`));
  console.log("");

  // Individual findings
  for (const finding of sorted) {
    const severityLabel = SEVERITY_COLORS[finding.severity](
      ` ${finding.severity.toUpperCase()} `,
    );
    const sourceLabel = finding.source === "ai"
      ? chalk.magenta(" [AI] ")
      : chalk.gray(` [${finding.rule}] `);

    console.log(`  ${severityLabel}${sourceLabel}${chalk.bold(finding.title)}`);
    console.log(chalk.gray(`  ${finding.file}:${finding.line}`));
    console.log("");

    // Description
    console.log(chalk.white(`  ${finding.description}`));
    console.log("");

    // Code snippet
    if (finding.snippet) {
      const snippetLines = finding.snippet.split("\n");
      for (const line of snippetLines) {
        if (line.startsWith(">")) {
          console.log(chalk.red(`    ${line}`));
        } else {
          console.log(chalk.gray(`    ${line}`));
        }
      }
      console.log("");
    }

    // Fix suggestion
    if (finding.fix) {
      console.log(chalk.green(`  Fix: ${finding.fix}`));
      console.log("");
    }

    console.log(chalk.gray("  " + "─".repeat(50)));
    console.log("");
  }

  // Footer
  if (counts.critical > 0) {
    console.log(
      chalk.bgRed.white.bold(" ACTION REQUIRED ") +
        chalk.red.bold(` ${counts.critical} critical issue${counts.critical > 1 ? "s" : ""} found. Fix these before deploying.`),
    );
  } else if (counts.high > 0) {
    console.log(
      chalk.yellow.bold(`  Recommendation: Address the ${counts.high} high-severity issue${counts.high > 1 ? "s" : ""} before going to production.`),
    );
  }

  console.log("");
}
