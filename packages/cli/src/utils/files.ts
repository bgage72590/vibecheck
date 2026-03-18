import fg from "fast-glob";
import ignore from "ignore";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const SOURCE_EXTENSIONS = [
  "js",
  "jsx",
  "ts",
  "tsx",
  "mjs",
  "cjs",
  "py",
  "html",
  "htm",
  "vue",
  "svelte",
  "php",
  "rb",
  "env",
  "yaml",
  "yml",
  "json",
  "toml",
  "sql",
];

const ALWAYS_IGNORE = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "coverage",
  ".turbo",
  "*.min.js",
  "*.min.css",
  "*.map",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
];

export async function collectFiles(directory: string): Promise<string[]> {
  const ig = ignore.default();

  // Load .gitignore if present
  const gitignorePath = join(directory, ".gitignore");
  if (existsSync(gitignorePath)) {
    const gitignoreContent = readFileSync(gitignorePath, "utf-8");
    ig.add(gitignoreContent);
  }

  // Always ignore these
  ig.add(ALWAYS_IGNORE);

  const patterns = SOURCE_EXTENSIONS.map((ext) => `**/*.${ext}`);
  // Also grab dotfiles like .env, .env.local, etc.
  patterns.push("**/.env*");

  const files = await fg(patterns, {
    cwd: directory,
    absolute: false,
    dot: true,
    onlyFiles: true,
    ignore: ALWAYS_IGNORE.map((p) => `**/${p}`),
  });

  // Apply .gitignore filtering
  return files.filter((file) => !ig.ignores(file));
}

export function readFileContents(
  directory: string,
  filePath: string,
): string | null {
  try {
    const fullPath = join(directory, filePath);
    return readFileSync(fullPath, "utf-8");
  } catch {
    return null;
  }
}

export function getSnippet(
  content: string,
  line: number,
  contextLines = 2,
): string {
  const lines = content.split("\n");
  const start = Math.max(0, line - 1 - contextLines);
  const end = Math.min(lines.length, line + contextLines);

  return lines
    .slice(start, end)
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === line ? ">" : " ";
      return `${marker} ${lineNum.toString().padStart(4)} | ${l}`;
    })
    .join("\n");
}
