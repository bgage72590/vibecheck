"use client";

import { useState, useCallback } from "react";
import { UploadZone } from "@/components/upload-zone";
import { StatCard } from "@/components/stat-card";
import { FindingCard } from "@/components/finding-card";
import type { Finding } from "@/lib/demo-data";
import Link from "next/link";

type ScanState = "idle" | "extracting" | "scanning" | "results" | "error";

interface ScanResults {
  findings: Finding[];
  filesScanned: number;
  duration: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  grade?: string;
  score?: number;
  gradeSummary?: string;
  frameworks?: string[];
  totalRules?: number;
}

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".vue", ".svelte", ".astro",
  ".py", ".rb", ".go", ".rs", ".java", ".php",
  ".swift", ".kt", ".kts", ".dart", ".cs",
  ".c", ".cpp", ".h",
  ".sh", ".bash", ".zsh",
  ".env", ".yaml", ".yml", ".toml", ".json", ".xml",
  ".html", ".htm", ".sql",
  ".properties", ".ini", ".cfg", ".conf",
  ".tf", ".hcl", ".dockerfile",
  ".erb", ".jinja", ".j2",
  ".gradle",
  ".r", ".lua", ".pl", ".pm", ".ex", ".exs",
  ".ipynb", ".md",
  ".prisma", ".plist", ".pbxproj", ".entitlements", ".rules", ".csv",
]);

const SOURCE_FILENAMES = new Set([
  "Dockerfile", "Makefile", "Gemfile", "Rakefile",
  ".env.local", ".env.production", ".env.development", ".env.example",
  "package.json", "Cargo.toml", "go.mod", "requirements.txt", "Pipfile",
  "next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
  "firebase.json", ".firebaserc", "firestore.rules",
  "app.json", "app.config.js", "eas.json",
  "wrangler.toml", "netlify.toml",
  "drizzle.config.ts", "drizzle.config.js",
  "Procfile", "Caddyfile", "nginx.conf",
  "AndroidManifest.xml",
]);

// Skip directories that are never useful to scan
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".build", "build", "dist", ".next",
  "__pycache__", ".gradle", "Pods", "DerivedData",
  "__MACOSX", ".app", ".framework", ".dSYM",
]);

function getExt(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.substring(dot).toLowerCase() : "";
}

function shouldSkipPath(path: string, ignorePatterns: string[] = []): boolean {
  const parts = path.split("/");
  for (const part of parts) {
    if (SKIP_DIRS.has(part)) return true;
    if (part.endsWith(".app") || part.endsWith(".framework") || part.endsWith(".dSYM")) return true;
  }
  // Check .vibecheckignore patterns
  for (const pattern of ignorePatterns) {
    if (!pattern || pattern.startsWith("#")) continue;
    const trimmed = pattern.trim();
    if (!trimmed) continue;
    // Simple matching: check if path starts with or contains the pattern
    if (path.startsWith(trimmed) || path.includes("/" + trimmed)) return true;
    // Handle trailing slash (directory patterns)
    if (trimmed.endsWith("/") && path.startsWith(trimmed.slice(0, -1))) return true;
  }
  return false;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://vibecheck-api-gs4b.vercel.app";

export default function ScanPage() {
  const [state, setState] = useState<ScanState>("idle");
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string>("");
  const [statusMessage, setStatusMessage] = useState("");

  const handleFilesSelected = useCallback(async (files: File[], isZip: boolean) => {
    setError("");

    try {
      let sourceFiles: { path: string; content: string }[] = [];

      if (isZip) {
        setState("extracting");

        const zipFile = files[0];

        // Warn if ZIP is very large (>100MB) — browser may struggle
        if (zipFile.size > 100 * 1024 * 1024) {
          setStatusMessage(`Large ZIP (${(zipFile.size / (1024*1024)).toFixed(0)}MB) — extracting, this may take a moment...`);
        } else {
          setStatusMessage("Extracting ZIP file...");
        }

        // Dynamic import to keep bundle small
        const { unzipSync } = await import("fflate");

        const zipBuffer = new Uint8Array(await zipFile.arrayBuffer());

        let entries: Record<string, Uint8Array>;
        try {
          entries = unzipSync(zipBuffer);
        } catch {
          setError("Invalid or corrupted ZIP file. Try re-zipping the project folder.");
          setState("error");
          return;
        }

        // Check for .vibecheckignore in the ZIP
        let ignorePatterns: string[] = [];
        for (const [path, data] of Object.entries(entries)) {
          const name = path.split("/").pop() || "";
          if (name === ".vibecheckignore") {
            try {
              ignorePatterns = new TextDecoder("utf-8").decode(data).split("\n");
            } catch { /* ignore */ }
            break;
          }
        }

        for (const [path, data] of Object.entries(entries)) {
          // Skip directories
          if (path.endsWith("/")) continue;
          // Skip build artifacts, node_modules, etc. BEFORE decoding
          if (shouldSkipPath(path, ignorePatterns)) continue;
          // Skip path traversal
          if (path.includes("..") || path.startsWith("/")) continue;
          // Check extension or filename BEFORE decoding
          const fileName = path.split("/").pop() || "";
          if (!SOURCE_EXTENSIONS.has(getExt(path)) && !SOURCE_FILENAMES.has(fileName)) continue;
          // Skip large files (>500KB is probably not source code)
          if (data.length > 500 * 1024) continue;

          try {
            // Create a fresh decoder per file — reusing with fatal:true can break
            const content = new TextDecoder("utf-8", { fatal: true }).decode(data);
            sourceFiles.push({ path, content });
          } catch {
            // Skip binary files that can't be decoded as UTF-8
          }
        }

        if (sourceFiles.length === 0) {
          setError("No scannable source files found in the ZIP. We scan .js, .ts, .py, .swift, .go, .env, and more.");
          setState("error");
          return;
        }

        setStatusMessage(`Found ${sourceFiles.length} source files. Scanning...`);
      } else {
        setState("extracting");
        setStatusMessage("Reading files...");

        for (const file of files) {
          try {
            const content = await file.text();
            sourceFiles.push({ path: file.name, content });
          } catch {
            // Skip unreadable files
          }
        }

        if (sourceFiles.length === 0) {
          setError("No readable source files found.");
          setState("error");
          return;
        }
      }

      // Now send just the source text as JSON (much smaller than the full ZIP)
      setState("scanning");
      setStatusMessage(`Scanning ${sourceFiles.length} files for vulnerabilities...`);

      const response = await fetch(`${API_URL}/api/scans/upload-json`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files: sourceFiles }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Scan failed. Please try again.");
        setState("error");
        return;
      }

      setResults(data);
      setState("results");
    } catch (err) {
      console.error("Scan error:", err);
      if (err instanceof TypeError && (err.message.includes("fetch") || err.message.includes("network"))) {
        setError("Failed to connect to the scan server. Please try again.");
      } else if (err instanceof RangeError || (err instanceof Error && err.message.includes("memory"))) {
        setError("ZIP file is too large to process in the browser. Try zipping only your source code folder (exclude .build, node_modules, etc).");
      } else {
        setError(`Scan failed: ${err instanceof Error ? err.message : "Unknown error"}. Please try again.`);
      }
      setState("error");
    }
  }, []);

  const handleReset = useCallback(() => {
    setState("idle");
    setResults(null);
    setError("");
    setStatusMessage("");
  }, []);

  const [copyLabel, setCopyLabel] = useState("Copy as AI Prompt");

  const generateMarkdownReport = useCallback((r: ScanResults): string => {
    const lines: string[] = [
      "# VibeCheck Security Report",
      "",
      r.grade ? `- **Security Grade:** ${r.grade} (${r.score}/100)` : "",
      r.frameworks && r.frameworks.length > 0 ? `- **Frameworks:** ${r.frameworks.join(", ")}` : "",
      `- **Files Scanned:** ${r.filesScanned}`,
      `- **Total Findings:** ${r.findings.length}`,
      `- **Critical:** ${r.criticalCount} | **High:** ${r.highCount} | **Medium:** ${r.mediumCount}`,
      `- **Scan Duration:** ${(r.duration / 1000).toFixed(1)}s`,
      "",
    ].filter(Boolean);

    const sorted = [...r.findings].sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    });

    for (const f of sorted) {
      lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push("");
      lines.push(`- **Rule:** ${f.rule}`);
      lines.push(`- **File:** \`${f.file}\` (line ${f.line})`);
      lines.push(`- **Category:** ${f.category}`);
      if (f.description) lines.push(`- **Why:** ${f.description}`);
      if (f.fix) lines.push(`- **Fix:** ${f.fix}`);
      if (f.snippet) {
        lines.push("");
        lines.push("```");
        lines.push(f.snippet);
        lines.push("```");
      }
      lines.push("");
    }

    return lines.join("\n");
  }, []);

  const generateAIPrompt = useCallback((r: ScanResults): string => {
    const lines: string[] = [
      "Fix the following security vulnerabilities found by VibeCheck. For each finding, apply the suggested fix. Do not change any other code.",
      "",
    ];

    const sorted = [...r.findings].sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    });

    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      lines.push(`### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`File: ${f.file}, Line: ${f.line}`);
      lines.push(`Problem: ${f.description || f.title}`);
      lines.push(`Fix: ${f.fix || "See rule " + f.rule}`);
      if (f.snippet) {
        lines.push("Current code:");
        lines.push("```");
        lines.push(f.snippet);
        lines.push("```");
      }
      lines.push("");
    }

    return lines.join("\n");
  }, []);

  const handleExportMarkdown = useCallback(() => {
    if (!results) return;
    const md = generateMarkdownReport(results);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vibecheck-report.md";
    a.click();
    URL.revokeObjectURL(url);
  }, [results, generateMarkdownReport]);

  const handleExportJSON = useCallback(() => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vibecheck-report.json";
    a.click();
    URL.revokeObjectURL(url);
  }, [results]);

  const handleCopyAIPrompt = useCallback(() => {
    if (!results) return;
    const prompt = generateAIPrompt(results);
    navigator.clipboard.writeText(prompt).then(() => {
      setCopyLabel("Copied!");
      setTimeout(() => setCopyLabel("Copy as AI Prompt"), 2000);
    });
  }, [results, generateAIPrompt]);

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <Link href="/" className="text-gray-500 text-sm hover:text-gray-400 transition-colors">
            &larr; Back to Dashboard
          </Link>
          <h1 className="text-2xl font-bold mt-1">Scan Your Code</h1>
          <p className="text-gray-500 text-sm">
            Upload your project files to scan for security vulnerabilities
          </p>
        </div>
      </div>

      {/* Upload zone (shown in idle state) */}
      {(state === "idle" || state === "error") && (
        <>
          <UploadZone onFilesSelected={handleFilesSelected} disabled={false} />

          {state === "error" && (
            <div className="mt-4 bg-red-900/20 border border-red-800 rounded-xl p-4 text-red-400">
              {error}
            </div>
          )}
        </>
      )}

      {/* Extracting / Scanning state */}
      {(state === "extracting" || state === "scanning") && (
        <div className="bg-[#1a1a2e] rounded-xl p-12 text-center">
          <div className="animate-spin text-4xl mb-4 inline-block">*</div>
          <p className="text-lg font-medium mb-2">
            {state === "extracting" ? "Preparing files..." : "Scanning for vulnerabilities..."}
          </p>
          <p className="text-gray-500 text-sm">
            {statusMessage}
          </p>
        </div>
      )}

      {/* Results */}
      {state === "results" && results && (
        <div className="space-y-6">
          {/* Grade banner */}
          {results.grade && (
            <div className={`rounded-xl p-6 flex items-center gap-6 ${
              results.grade === "A+" || results.grade === "A" ? "bg-green-900/20 border border-green-800" :
              results.grade === "B" ? "bg-cyan-900/20 border border-cyan-800" :
              results.grade === "C" ? "bg-yellow-900/20 border border-yellow-800" :
              "bg-red-900/20 border border-red-800"
            }`}>
              <div className={`text-5xl font-black ${
                results.grade === "A+" || results.grade === "A" ? "text-green-400" :
                results.grade === "B" ? "text-cyan-400" :
                results.grade === "C" ? "text-yellow-400" :
                "text-red-400"
              }`}>
                {results.grade}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <span className="text-lg font-semibold">Security Grade</span>
                  <span className="text-gray-500 text-sm">{results.score}/100</span>
                </div>
                <p className="text-gray-400 text-sm">{results.gradeSummary}</p>
                {results.frameworks && results.frameworks.length > 0 && (
                  <div className="flex gap-2 mt-2">
                    {results.frameworks.map((fw) => (
                      <span key={fw} className="px-2 py-0.5 bg-gray-700/50 rounded text-xs text-gray-300">
                        {fw}
                      </span>
                    ))}
                    {results.totalRules && (
                      <span className="px-2 py-0.5 bg-gray-700/50 rounded text-xs text-gray-300">
                        {results.totalRules} rules
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Summary stats */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <StatCard
              label="Critical"
              value={results.criticalCount}
              color="text-red-400"
            />
            <StatCard
              label="High"
              value={results.highCount}
              color="text-orange-400"
            />
            <StatCard
              label="Medium"
              value={results.mediumCount}
              color="text-yellow-400"
            />
            <StatCard
              label="Files Scanned"
              value={results.filesScanned}
              color="text-cyan-400"
            />
            <StatCard
              label="Total Findings"
              value={results.findings.length}
              color={results.findings.length > 0 ? "text-red-400" : "text-green-400"}
            />
          </div>

          {/* Scan metadata + actions */}
          <div className="bg-[#1a1a2e] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-gray-400 text-sm">
                Scanned {results.filesScanned} files in {(results.duration / 1000).toFixed(1)}s
              </p>
              <button
                type="button"
                onClick={handleReset}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-medium transition-colors"
              >
                Scan Again
              </button>
            </div>

            {results.findings.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-3 border-t border-gray-700">
                <button
                  type="button"
                  onClick={handleCopyAIPrompt}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-500 rounded-lg text-sm font-medium transition-colors"
                >
                  {copyLabel}
                </button>
                <button
                  type="button"
                  onClick={handleExportMarkdown}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                >
                  Export Markdown
                </button>
                <button
                  type="button"
                  onClick={handleExportJSON}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                >
                  Export JSON
                </button>
              </div>
            )}
          </div>

          {/* No findings message */}
          {results.findings.length === 0 && (
            <div className="bg-green-900/20 border border-green-800 rounded-xl p-8 text-center">
              <div className="text-4xl mb-3">OK</div>
              <p className="text-green-400 text-lg font-medium">No vulnerabilities found!</p>
              <p className="text-gray-500 text-sm mt-1">
                Your code looks clean. Keep up the good security practices.
              </p>
            </div>
          )}

          {/* Findings list */}
          {results.findings.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold mb-4">
                Findings ({results.findings.length})
              </h2>
              <div className="space-y-4">
                {results.findings
                  .sort((a, b) => {
                    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
                  })
                  .map((finding) => (
                    <FindingCard key={finding.id} finding={finding} />
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* How it works */}
      {state === "idle" && (
        <div className="mt-8 bg-[#1a1a2e] rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-3">How it works</h2>
          <div className="grid sm:grid-cols-3 gap-4 text-sm text-gray-400">
            <div>
              <div className="text-cyan-400 font-medium mb-1">1. Upload</div>
              <p>Drop your project files or a ZIP. We extract only source code — binaries and build artifacts are automatically skipped.</p>
            </div>
            <div>
              <div className="text-cyan-400 font-medium mb-1">2. Scan</div>
              <p>Our engine runs 78 security rules checking for hardcoded secrets, SQL injection, XSS, SSRF, NoSQL injection, weak crypto, Electron misconfigs, Docker/K8s security, CI/CD vulnerabilities, and more.</p>
            </div>
            <div>
              <div className="text-cyan-400 font-medium mb-1">3. Fix</div>
              <p>Get plain-English explanations and fix suggestions for every vulnerability found.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
