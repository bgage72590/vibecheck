import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { loginCommand, logoutCommand, whoamiCommand } from "./commands/auth.js";

const program = new Command();

program
  .name("vibecheck")
  .description(
    "AI security scanner for vibe-coded apps. Find vulnerabilities before attackers do.",
  )
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a directory for security vulnerabilities")
  .argument("[directory]", "Directory to scan", ".")
  .option("--no-ai", "Skip AI-powered analysis")
  .option("-f, --format <format>", "Output format: terminal, json, sarif", "terminal")
  .option("-v, --verbose", "Show detailed output", false)
  .action(async (directory: string, opts: { ai: boolean; format: string; verbose: boolean }) => {
    await scanCommand(directory, {
      directory,
      aiAnalysis: opts.ai,
      format: opts.format as "terminal" | "json" | "sarif",
      verbose: opts.verbose,
    });
  });

// Auth commands
const auth = program
  .command("auth")
  .description("Manage authentication");

auth
  .command("login")
  .description("Log in to your VibeCheck account")
  .action(loginCommand);

auth
  .command("logout")
  .description("Log out of your VibeCheck account")
  .action(logoutCommand);

auth
  .command("whoami")
  .description("Show current logged-in user")
  .action(whoamiCommand);

// Upgrade command (shortcut)
program
  .command("upgrade")
  .description("Upgrade to VibeCheck Pro for unlimited scans")
  .action(async () => {
    const { getStoredToken, getCheckoutUrl } = await import("./utils/api.js");
    const chalk = (await import("chalk")).default;

    const token = getStoredToken();
    if (!token) {
      console.log(chalk.yellow("Please log in first: vibecheck auth login"));
      return;
    }

    console.log(chalk.cyan("Creating checkout session..."));
    const url = await getCheckoutUrl();
    if (url) {
      console.log(chalk.green(`\nOpen this URL to upgrade:`));
      console.log(chalk.bold.underline(url));
      const { execFile } = require("node:child_process");
      const openCmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
      execFile(openCmd, [url], () => {});
    } else {
      console.log(chalk.red("Failed to create checkout session. Please try again."));
    }
  });

program.parse();
