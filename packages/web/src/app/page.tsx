import Link from "next/link";
import { StatCard } from "@/components/stat-card";
import { TrendChart } from "@/components/trend-chart";
import { ScanTable } from "@/components/scan-table";
import { demoScans, trendData } from "@/lib/demo-data";

export default function DashboardPage() {
  const latestScan = demoScans[0];
  const totalFindings = demoScans.reduce((s, scan) => s + scan.findingsCount, 0);
  const totalCritical = demoScans.reduce((s, scan) => s + scan.criticalCount, 0);

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-cyan-400">vibecheck</h1>
          <p className="text-gray-500 text-sm">Security Dashboard</p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/scan"
            className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg text-sm font-medium transition-colors"
          >
            Scan Now
          </Link>
          <span className="text-xs px-3 py-1 rounded-full bg-gray-800 text-gray-400">
            FREE PLAN
          </span>
          <span className="text-sm text-gray-500">dev@vibecheck.dev</span>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Scans" value={demoScans.length} />
        <StatCard
          label="Critical Issues"
          value={totalCritical}
          color="text-red-400"
        />
        <StatCard
          label="Total Findings"
          value={totalFindings}
          color="text-orange-400"
        />
        <StatCard
          label="Files Scanned"
          value={latestScan.filesScanned}
          color="text-cyan-400"
        />
      </div>

      {/* Trend Chart */}
      <div className="mb-8">
        <TrendChart data={trendData} />
      </div>

      {/* Scan History */}
      <ScanTable scans={demoScans} />

      {/* Quick Start */}
      <div className="mt-8 bg-[#1a1a2e] rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-3">Quick Start</h2>
        <div className="space-y-3">
          <div>
            <p className="text-gray-400 text-sm mb-1">
              Scan your project from the terminal:
            </p>
            <code className="block bg-[#12121f] rounded-lg p-3 text-sm font-mono text-cyan-400">
              npx vibecheck scan .
            </code>
          </div>
          <div>
            <p className="text-gray-400 text-sm mb-1">
              Add to your CI pipeline:
            </p>
            <code className="block bg-[#12121f] rounded-lg p-3 text-sm font-mono text-cyan-400">
              npx vibecheck scan . --format sarif --no-ai
            </code>
          </div>
        </div>
      </div>
    </div>
  );
}
