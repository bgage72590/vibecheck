import Link from "next/link";
import type { ScanSummary } from "@/lib/demo-data";

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function ScanTable({ scans }: { scans: ScanSummary[] }) {
  return (
    <div className="bg-[#1a1a2e] rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-800">
        <h2 className="text-lg font-semibold">Recent Scans</h2>
      </div>
      <table className="w-full">
        <thead>
          <tr className="text-xs uppercase text-gray-500 border-b border-gray-800">
            <th className="text-left px-6 py-3">Directory</th>
            <th className="text-center px-3 py-3">Files</th>
            <th className="text-center px-3 py-3">Critical</th>
            <th className="text-center px-3 py-3">High</th>
            <th className="text-center px-3 py-3">Medium</th>
            <th className="text-center px-3 py-3">Total</th>
            <th className="text-right px-6 py-3">When</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="border-b border-gray-800/50 hover:bg-[#22223a] transition-colors"
            >
              <td className="px-6 py-3">
                <Link
                  href={`/scans/${scan.id}`}
                  className="text-cyan-400 hover:underline font-mono text-sm"
                >
                  {scan.directory}
                </Link>
              </td>
              <td className="text-center px-3 py-3 text-gray-400 text-sm">
                {scan.filesScanned}
              </td>
              <td className="text-center px-3 py-3">
                {scan.criticalCount > 0 ? (
                  <span className="text-red-400 font-bold">
                    {scan.criticalCount}
                  </span>
                ) : (
                  <span className="text-gray-600">0</span>
                )}
              </td>
              <td className="text-center px-3 py-3">
                {scan.highCount > 0 ? (
                  <span className="text-orange-400 font-bold">
                    {scan.highCount}
                  </span>
                ) : (
                  <span className="text-gray-600">0</span>
                )}
              </td>
              <td className="text-center px-3 py-3">
                {scan.mediumCount > 0 ? (
                  <span className="text-yellow-400">{scan.mediumCount}</span>
                ) : (
                  <span className="text-gray-600">0</span>
                )}
              </td>
              <td className="text-center px-3 py-3 font-semibold">
                {scan.findingsCount}
              </td>
              <td className="text-right px-6 py-3 text-gray-500 text-sm">
                {timeAgo(scan.createdAt)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
