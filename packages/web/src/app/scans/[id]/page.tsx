import { notFound } from "next/navigation";
import Link from "next/link";
import { StatCard } from "@/components/stat-card";
import { FindingCard } from "@/components/finding-card";
import { demoScans, demoFindings } from "@/lib/demo-data";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = demoScans.find((s) => s.id === id);
  if (!scan) {
    return notFound();
  }

  return (
    <div className="max-w-4xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="mb-6">
        <Link
          href="/"
          className="text-gray-500 hover:text-cyan-400 text-sm mb-2 inline-block"
        >
          &larr; Back to Dashboard
        </Link>
        <h1 className="text-xl font-bold">
          Scan: <span className="text-cyan-400 font-mono">{scan.directory}</span>
        </h1>
        <p className="text-gray-500 text-sm mt-1">
          {new Date(scan.createdAt).toLocaleString()} &middot;{" "}
          {scan.filesScanned} files &middot; {(scan.duration / 1000).toFixed(1)}s
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">
        <StatCard
          label="Critical"
          value={scan.criticalCount}
          color="text-red-400"
        />
        <StatCard
          label="High"
          value={scan.highCount}
          color="text-orange-400"
        />
        <StatCard
          label="Medium"
          value={scan.mediumCount}
          color="text-yellow-400"
        />
        <StatCard label="Low" value={scan.lowCount} color="text-blue-400" />
        <StatCard label="Total" value={scan.findingsCount} />
      </div>

      {/* Findings */}
      <h2 className="text-lg font-semibold mb-4">Findings</h2>
      <div className="space-y-4">
        {demoFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  );
}
