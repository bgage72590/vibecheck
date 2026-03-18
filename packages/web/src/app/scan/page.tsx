"use client";

import { useState, useCallback } from "react";
import { UploadZone } from "@/components/upload-zone";
import { StatCard } from "@/components/stat-card";
import { FindingCard } from "@/components/finding-card";
import type { Finding } from "@/lib/demo-data";
import Link from "next/link";

type ScanState = "idle" | "scanning" | "results" | "error";

interface ScanResults {
  findings: Finding[];
  filesScanned: number;
  duration: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://vibecheck-api-gs4b.vercel.app";

export default function ScanPage() {
  const [state, setState] = useState<ScanState>("idle");
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string>("");
  const [scanningFileCount, setScanningFileCount] = useState(0);

  const handleFilesSelected = useCallback(async (files: File[], isZip: boolean) => {
    setState("scanning");
    setScanningFileCount(files.length);
    setError("");

    try {
      const formData = new FormData();

      if (isZip) {
        formData.append("zip", files[0]);
      } else {
        for (const file of files) {
          formData.append("files", file, file.name);
        }
      }

      const response = await fetch(`${API_URL}/api/scans/upload`, {
        method: "POST",
        body: formData,
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
      setError("Failed to connect to the scan server. Please try again.");
      setState("error");
    }
  }, []);

  const handleReset = useCallback(() => {
    setState("idle");
    setResults(null);
    setError("");
  }, []);

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

      {/* Scanning state */}
      {state === "scanning" && (
        <div className="bg-[#1a1a2e] rounded-xl p-12 text-center">
          <div className="animate-spin text-4xl mb-4 inline-block">*</div>
          <p className="text-lg font-medium mb-2">Scanning files...</p>
          <p className="text-gray-500 text-sm">
            Analyzing {scanningFileCount} file{scanningFileCount > 1 ? "s" : ""} for security vulnerabilities
          </p>
        </div>
      )}

      {/* Results */}
      {state === "results" && results && (
        <div className="space-y-6">
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

          {/* Scan metadata */}
          <div className="bg-[#1a1a2e] rounded-xl p-4 flex items-center justify-between">
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
              <p>Drop your project files or upload a ZIP. We accept JavaScript, TypeScript, Python, and more.</p>
            </div>
            <div>
              <div className="text-cyan-400 font-medium mb-1">2. Scan</div>
              <p>Our engine runs 10 security rules checking for hardcoded secrets, SQL injection, XSS, missing auth, and more.</p>
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
